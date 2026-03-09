/**
 * Auth server: signup, login, JWT.
 * 1. Imports: express, bcryptjs, jsonwebtoken, dotenv, db pool
 * 2. POST /signup: username, email, phone, password → hash, insert users → "Account created successfully!"
 * 3. POST /login: username, password → compare → "Hello, username! 👋" + token
 * 4. Input validation on both routes → { "error": "..." } with 400, 401, 409, 500
 * 5. Duplicate username/email → specific messages (409)
 * 6. JWT expires in 1d, JWT_SECRET from .env
 * 7. Listens on PORT from .env
 * 8. Uses existing db.js, .env, ca.pem (via DB_SSL_CA)
 */
require('dotenv').config();
const path = require('path');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');

const app = express();
app.use(express.json());
app.use(express.static(__dirname));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ---------- Startup: required env variables ----------
const REQUIRED_ENV = ['DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'DB_SSL_CA', 'JWT_SECRET', 'PORT'];
function checkEnv() {
  const missing = REQUIRED_ENV.filter((key) => !process.env[key] || process.env[key].trim() === '');
  if (missing.length > 0) {
    console.error('Missing required environment variable(s):', missing.join(', '));
    process.exit(1);
  }
}

// ---------- Validation helpers ----------
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_MIN = 3;
const USERNAME_MAX = 50;
const PASSWORD_MIN = 6;

function validateSignup(body) {
  const username = typeof body.username === 'string' ? body.username.trim() : '';
  const email = typeof body.email === 'string' ? body.email.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  const phone = body.phone != null ? String(body.phone).trim() : '';

  if (!username) return { error: 'Username is required' };
  if (username.length < USERNAME_MIN || username.length > USERNAME_MAX) {
    return { error: `Username must be between ${USERNAME_MIN} and ${USERNAME_MAX} characters` };
  }
  if (!email) return { error: 'Email is required' };
  if (!EMAIL_REGEX.test(email)) return { error: 'Email is invalid' };
  if (!password) return { error: 'Password is required' };
  if (password.length < PASSWORD_MIN) {
    return { error: `Password must be at least ${PASSWORD_MIN} characters` };
  }
  return { username, email, phone, password };
}

function validateLogin(body) {
  const username = typeof body.username === 'string' ? body.username.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!username || !password) {
    return { error: 'Username and password are required' };
  }
  return { username, password };
}

// ---------- JWT middleware ----------
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Access denied. Token required.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token expired. Please log in again.' });
      }
      return res.status(401).json({ error: 'Invalid token.' });
    }
    req.user = decoded;
    next();
  });
}

// ---------- Routes ----------

// SIGNUP
app.post('/signup', async (req, res, next) => {
  const validated = validateSignup(req.body);
  if (validated.error) {
    return res.status(400).json({ error: validated.error });
  }
  const { username, email, phone, password } = validated;

  try {
    const [existingUsername] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
    if (existingUsername.length > 0) {
      return res.status(409).json({ error: 'Username already taken' });
    }
    const [existingEmail] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existingEmail.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, email, phone, password) VALUES (?, ?, ?, ?)',
      [username, email, phone || null, hashedPassword]
    );
    res.json({ message: 'Account created successfully!' });
  } catch (err) {
    console.error('[SIGNUP ERROR]', err.message, '| code:', err.code, '| stack:', err.stack);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    next(err);
  }
});

// LOGIN
app.post('/login', async (req, res, next) => {
  const validated = validateLogin(req.body);
  if (validated.error) {
    return res.status(400).json({ error: validated.error });
  }
  const { username, password } = validated;

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    res.json({
      message: `Hello, ${user.username}! 👋`,
      token
    });
  } catch (err) {
    console.error('[LOGIN ERROR]', err.message, '| code:', err.code, '| stack:', err.stack);
    next(err);
  }
});

// Protected route
app.get('/me', authenticateToken, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username });
});

// ---------- Central error handler ----------
app.use((err, req, res, next) => {
  console.error('Server error (exact):', err.message);
  console.error('Error code:', err.code);
  console.error('Stack:', err.stack);
  res.status(500).json({ error: 'Server error. Please try again later.' });
});

// ---------- Start server (after env + DB check) ----------
const USERS_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(20),
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`;

async function start() {
  checkEnv();
  console.log('Env OK:', REQUIRED_ENV.join(', '));
  try {
    await pool.query('SELECT 1');
  } catch (err) {
    console.error('Database connection failed:', err.message);
    console.error('Stack:', err.stack);
    process.exit(1);
  }

  try {
    await pool.query(USERS_TABLE_SQL);
    console.log('Users table ready.');
  } catch (err) {
    console.error('Failed to ensure users table:', err.message);
    process.exit(1);
  }

  try {
    await pool.query('ALTER TABLE users ADD COLUMN phone VARCHAR(20)');
    console.log('Added phone column to users table.');
  } catch (err) {
    if (err.code === 'ER_DUP_FIELDNAME') {
      console.log('Users table already has phone column.');
    } else {
      console.error('Failed to add phone column:', err.message);
      process.exit(1);
    }
  }

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

start().catch((err) => {
  console.error('Failed to start server:', err.message);
  process.exit(1);
});
