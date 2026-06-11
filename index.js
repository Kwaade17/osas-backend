const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// CORS Restrictions
const allowedOrigins = [
  'http://localhost:5173', 
  'https://osas-frontend.vercel.app' 
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true
}));

// Set JSON limits to 5MB to handle Base64 uploads safely
app.use(express.json({ limit: '5mb' }));

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    console.warn('Bad Request: Malformed JSON payload received.');
    return res.status(400).json({ error: 'Invalid JSON format in request body.' });
  }
  next();
});

// Rate Limiters
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100, 
  message: { error: 'Too many requests from this IP, please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message: { error: 'Too many login attempts. Access temporarily restricted. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(generalLimiter);

// PostgreSQL Pool Connection
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
      }
    : {
        user: process.env.DB_USER,
        host: process.env.DB_HOST,
        database: process.env.DB_DATABASE,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
      }
);

// Test Database Connection
pool.connect((err, client, release) => {
  if (err) {
    return console.error('Error acquiring client from pool:', err.stack);
  }
  console.log('Successfully connected to PostgreSQL database!');
  release();
});

// ==========================================
// SECURITY MIDDLEWARES
// ==========================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. Please log in.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Session expired or invalid. Please log in again.' });
    }
    req.user = user;
    next();
  });
};

const requireDeveloper = (req, res, next) => {
  if (req.user.role !== 'developer') {
    return res.status(403).json({ error: 'Access denied. Developer privileges required.' });
  }
  next();
};

// ==========================================
// AUTHENTICATION ROUTES
// ==========================================

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required.' });
  }

  try {
    const userExist = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExist.rows.length > 0) {
      return res.status(400).json({ error: 'User with this email already exists.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const userRole = role || 'admin';

    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role',
      [name, email, passwordHash, userRole]
    );

    res.status(201).json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error('Registration error:', error.message);
    res.status(500).json({ error: 'Server error, could not create account.' });
  }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    res.status(200).json({
      success: true,
      message: 'Login successful!',
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Server error, could not process login.' });
  }
});

// ==========================================
// DYNAMIC SITE SERVICES & PROGRAMS API
// ==========================================

app.get('/api/site-services', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM site_services ORDER BY id ASC');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not fetch site services.' });
  }
});

app.post('/api/site-services', authenticateToken, requireDeveloper, async (req, res) => {
  const { title, description, icon_class, service_type } = req.body;

  if (!title || !description || !icon_class || !service_type) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO site_services (title, description, icon_class, service_type) VALUES ($1, $2, $3, $4) RETURNING *',
      [title, description, icon_class, service_type]
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not create service/program.' });
  }
});

app.put('/api/site-services/:id', authenticateToken, requireDeveloper, async (req, res) => {
  const { id } = req.params;
  const { title, description, icon_class, service_type } = req.body;

  if (!title || !description || !icon_class || !service_type) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const result = await pool.query(
      'UPDATE site_services SET title = $1, description = $2, icon_class = $3, service_type = $4 WHERE id = $5 RETURNING *',
      [title, description, icon_class, service_type, id]
    );
    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not update service/program.' });
  }
});

// ==========================================
// DYNAMIC HOME LANDING CONTENT API
// ==========================================

app.get('/api/home', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM home_content LIMIT 1');
    res.status(200).json(result.rows[0] || {});
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not fetch Home content.' });
  }
});

app.put('/api/home', authenticateToken, requireDeveloper, async (req, res) => {
  const { hero_title, hero_subtitle, hero_bg_image } = req.body;

  if (!hero_title || !hero_subtitle || !hero_bg_image) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const result = await pool.query(
      'UPDATE home_content SET hero_title = $1, hero_subtitle = $2, hero_bg_image = $3 WHERE id = 1 RETURNING *',
      [hero_title, hero_subtitle, hero_bg_image]
    );
    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not update Home content.' });
  }
});

// ==========================================
// DYNAMIC ABOUT PAGE API
// ==========================================

app.get('/api/about', async (req, res) => {
  try {
    const content = await pool.query('SELECT * FROM about_content LIMIT 1');
    const functionalAreas = await pool.query('SELECT * FROM about_functional_areas ORDER BY id ASC');
    const staff = await pool.query('SELECT * FROM about_staff ORDER BY id ASC');

    res.status(200).json({
      content: content.rows[0] || {},
      functionalAreas: functionalAreas.rows,
      staff: staff.rows
    });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not fetch About content.' });
  }
});

app.put('/api/about/content', authenticateToken, requireDeveloper, async (req, res) => {
  const { heading, subheading, vision, mission } = req.body;

  if (!heading || !subheading || !vision || !mission) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const result = await pool.query(
      'UPDATE about_content SET heading = $1, subheading = $2, vision = $3, mission = $4 WHERE id = 1 RETURNING *',
      [heading, subheading, vision, mission]
    );
    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not save modifications.' });
  }
});

app.post('/api/about/functional-areas', authenticateToken, requireDeveloper, async (req, res) => {
  const { title, description, key_operations } = req.body;

  if (!title || !description || !key_operations) {
    return res.status(400).json({ error: 'All fields are required to register a functional area.' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO about_functional_areas (title, description, key_operations) VALUES ($1, $2, $3) RETURNING *',
      [title, description, key_operations]
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not create card.' });
  }
});

app.put('/api/about/functional-areas/:id', authenticateToken, requireDeveloper, async (req, res) => {
  const { id } = req.params;
  const { title, description, key_operations } = req.body;

  if (!title || !description || !key_operations) {
    return res.status(400).json({ error: 'All card fields are required.' });
  }

  try {
    const result = await pool.query(
      'UPDATE about_functional_areas SET title = $1, description = $2, key_operations = $3 WHERE id = $4 RETURNING *',
      [title, description, key_operations, id]
    );
    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not save card updates.' });
  }
});

app.post('/api/about/staff', authenticateToken, requireDeveloper, async (req, res) => {
  const { name, role, initials, color } = req.body;

  if (!name || !role || !initials) {
    return res.status(400).json({ error: 'All fields are required to add a staff profile.' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO about_staff (name, role, initials, color) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, role, initials, color || 'bg-emerald-800']
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not save staff.' });
  }
});

app.put('/api/about/staff/:id', authenticateToken, requireDeveloper, async (req, res) => {
  const { id } = req.params;
  const { name, role, initials, color } = req.body;

  if (!name || !role || !initials) {
    return res.status(400).json({ error: 'All staff fields are required.' });
  }

  try {
    const result = await pool.query(
      'UPDATE about_staff SET name = $1, role = $2, initials = $3, color = $4 WHERE id = $5 RETURNING *',
      [name, role, initials, color || 'bg-emerald-800', id]
    );
    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not save staff updates.' });
  }
});

// ==========================================
// DYNAMIC NAVIGATION SERVICES PAGE CONTENT API (New)
// ==========================================

// GET: Publicly read dynamic contents of the actual Services Page [1]
app.get('/api/services-page', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM services_page_content ORDER BY id ASC');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not fetch Services page content.' });
  }
});

// PUT: Save updated text/sidebars of a Services Page block (SECURED: Developer only) [1]
app.put('/api/services-page/:id', authenticateToken, requireDeveloper, async (req, res) => {
  const { id } = req.params;
  const { 
    title, icon_emoji, description, 
    feature_one_title, feature_one_desc, 
    feature_two_title, feature_two_desc, 
    feature_three_title, feature_three_desc, 
    instructions, sidebar_title, sidebar_text, 
    btn_primary_text, btn_secondary_text 
  } = req.body;

  if (!title || !icon_emoji || !description || !feature_one_title || !feature_one_desc || !feature_two_title || !feature_two_desc || !sidebar_title || !sidebar_text || !btn_primary_text || !btn_secondary_text) {
    return res.status(400).json({ error: 'All required text parameters are missing.' });
  }

  try {
    const queryText = `
      UPDATE services_page_content SET 
        title = $1, icon_emoji = $2, description = $3, 
        feature_one_title = $4, feature_one_desc = $5, 
        feature_two_title = $6, feature_two_desc = $7, 
        feature_three_title = $8, feature_three_desc = $9, 
        instructions = $10, sidebar_title = $11, sidebar_text = $12, 
        btn_primary_text = $13, btn_secondary_text = $14
      WHERE id = $15 RETURNING *
    `;
    const values = [
      title, icon_emoji, description, 
      feature_one_title, feature_one_desc, 
      feature_two_title, feature_two_desc, 
      feature_three_title || '', feature_three_desc || '', 
      instructions || '', sidebar_title, sidebar_text, 
      btn_primary_text, btn_secondary_text, id
    ];
    const result = await pool.query(queryText, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Service page block not found.' });
    }

    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not save changes.' });
  }
});

// ==========================================
// ORGANIZATIONS API
// ==========================================

app.get('/api/organizations', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM organizations ORDER BY name ASC');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not fetch organizations.' });
  }
});

app.post('/api/organizations', authenticateToken, async (req, res) => {
  const { name, acronym, org_type, description, adviser } = req.body;

  if (!name || !acronym || !org_type || !description || !adviser) {
    return res.status(400).json({ error: 'All fields are required to register an organization.' });
  }

  try {
    const queryText = `
      INSERT INTO organizations (name, acronym, org_type, description, adviser)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `;
    const values = [name, acronym, org_type, description, adviser];
    const result = await pool.query(queryText, values);
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not register organization.' });
  }
});

app.patch('/api/organizations/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, acronym, org_type, description, adviser, latest_update } = req.body;

  try {
    const updates = [];
    const values = [];
    let idx = 1;

    if (name) { updates.push(`name = $${idx++}`); values.push(name); }
    if (acronym) { updates.push(`acronym = $${idx++}`); values.push(acronym); }
    if (org_type) { updates.push(`org_type = $${idx++}`); values.push(org_type); }
    if (description) { updates.push(`description = $${idx++}`); values.push(description); }
    if (adviser) { updates.push(`adviser = $${idx++}`); values.push(adviser); }
    if (latest_update) { updates.push(`latest_update = $${idx++}`); values.push(latest_update); }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields provided to update.' });
    }

    values.push(id);
    const queryText = `UPDATE organizations SET ${updates.join(', ')} WHERE id = $${idx} RETURNING *`;
    const result = await pool.query(queryText, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Organization not found.' });
    }

    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not update organization.' });
  }
});

// ==========================================
// ANNOUNCEMENTS API
// ==========================================

app.get('/api/announcements', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM announcements ORDER BY published_date DESC');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not fetch announcements.' });
  }
});

app.post('/api/announcements', authenticateToken, async (req, res) => {
  const { title, category, summary, content, image_url } = req.body;

  if (!title || !category || !summary) {
    return res.status(400).json({ error: 'Title, category, and summary are required fields.' });
  }

  try {
    const queryText = `
      INSERT INTO announcements (title, category, summary, content, image_url) 
      VALUES ($1, $2, $3, $4, $5) 
      RETURNING *
    `;
    const values = [title, category, summary, content || '', image_url || ''];
    const result = await pool.query(queryText, values);
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not post announcement.' });
  }
});

// ==========================================
// CONTACT MESSAGES API
// ==========================================

app.get('/api/contact', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM contact_messages ORDER BY created_at DESC');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not fetch contact messages.' });
  }
});

app.post('/api/contact', async (req, res) => {
  const { name, email, department, message } = req.body;

  if (!name || !email || !department || !message) {
    return res.status(400).json({ error: 'All form fields are required.' });
  }

  try {
    const queryText = `
      INSERT INTO contact_messages (name, email, department, message) 
      VALUES ($1, $2, $3, $4) 
      RETURNING *
    `;
    const values = [name, email, department, message];
    const result = await pool.query(queryText, values);
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not save submission.' });
  }
});

// ==========================================
// APPOINTMENTS API
// ==========================================

app.get('/api/appointments', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM appointments ORDER BY appointment_date DESC, appointment_time DESC');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not fetch appointments.' });
  }
});

app.post('/api/appointments', async (req, res) => {
  const { student_name, student_id_num, student_email, counselor_name, appointment_date, appointment_time, reason } = req.body;

  if (!student_name || !student_id_num || !student_email || !counselor_name || !appointment_date || !appointment_time || !reason) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const queryText = `
      INSERT INTO appointments (student_name, student_id_num, student_email, counselor_name, appointment_date, appointment_time, reason) 
      VALUES ($1, $2, $3, $4, $5, $6, $7) 
      RETURNING *
    `;
    const values = [student_name, student_id_num, student_email, counselor_name, appointment_date, appointment_time, reason];
    const result = await pool.query(queryText, values);
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not save appointment.' });
  }
});

app.patch('/api/appointments/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!status) {
    return res.status(400).json({ error: 'Status is required.' });
  }

  try {
    const result = await pool.query(
      'UPDATE appointments SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Appointment record not found.' });
    }

    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not update appointment status.' });
  }
});

// ==========================================
// REQUEST ID API
// ==========================================

app.get('/api/id_request_process', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM id_request_process ORDER BY request_at');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not fetch appointments.' });
  }
});

app.post('/api/id_request_process', async (req, res) => {
  const { request_type, programs, first_name, middle_name, last_name, year_level, request_at } = req.body;

  if (!request_type || !programs || !first_name || !middle_name || !last_name || !year_level || !request_at) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const queryText = `
      INSERT INTO id_request_process (request_type, programs, first_name, middle_name, last_name, year_level, request_at) 
      VALUES ($1, $2, $3, $4, $5, $6, $7) 
      RETURNING *
    `;
    const values = [request_type, programs, first_name, middle_name, last_name, year_level, request_at];
    const result = await pool.query(queryText, values);
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error('Database query error:', error.message);
    res.status(500).json({ error: 'Server error, could not save request.' });
  }
});

// Base Route
app.get('/', (req, res) => {
  res.send('OSAS API Server is running.');
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});