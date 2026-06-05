const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit'); // Added Rate Limiting
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ==========================================
// SECURITY CONFIGURATION: CORS RESTRICTION
// ==========================================
// Replace the Vercel link below with your actual, live deployed Vercel URL
const allowedOrigins = [
  'http://localhost:5173', // Local frontend development
  'https://osas-frontend.vercel.app' // Your live deployed Vercel frontend URL
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, system checks, or seed curls)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true
}));

app.use(express.json());

// Catch malformed JSON payload errors gracefully
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    console.warn('Bad Request: Malformed JSON payload received.');
    return res.status(400).json({ error: 'Invalid JSON format in request body.' });
  }
  next();
});

// ==========================================
// SECURITY CONFIGURATION: RATE LIMITERS
// ==========================================
// 1. General Rate Limiter (Prevents DDoS and database spamming)
// Limits each IP to 100 requests per 15 minutes
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, 
  message: { error: 'Too many requests from this IP, please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// 2. Strict Auth Limiter (Prevents Brute-force password guessing)
// Limits each IP to 5 login attempts per 15 minutes
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, 
  message: { error: 'Too many login attempts. Access temporarily restricted. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply the general rate limiter globally to all API routes
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
// SECURITY MIDDLEWARE (Route Guard)
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

// ==========================================
// AUTHENTICATION ROUTES
// ==========================================

// POST: Register/Seed Admin Account
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

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

    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, passwordHash]
    );

    res.status(201).json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error('Registration error:', error.message);
    res.status(500).json({ error: 'Server error, could not create account.' });
  }
});

// POST: Login Route (SECURED: Uses strict login rate limiting)
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
      { id: user.id, email: user.email, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    res.status(200).json({
      success: true,
      message: 'Login successful!',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Server error, could not process login.' });
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
  const { title, category, summary, content } = req.body;

  if (!title || !category || !summary) {
    return res.status(400).json({ error: 'Title, category, and summary are required fields.' });
  }

  try {
    const queryText = `
      INSERT INTO announcements (title, category, summary, content) 
      VALUES ($1, $2, $3, $4) 
      RETURNING *
    `;
    const values = [title, category, summary, content || ''];
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

app.get('/api/appointments', authenticateToken, async (req, res) => {
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

// Base Route
app.get('/', (req, res) => {
  res.send('OSAS API Server is running.');
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});