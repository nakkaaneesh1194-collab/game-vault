// server.js - Simple Node.js backend for key validation
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3030;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static('public')); // Serve static files (index.html, games.html, etc.)

// Initialize SQLite database
const db = new sqlite3.Database('./keys.db', (err) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Connected to SQLite database');
        initDatabase();
    }
});

// Create tables if they don't exist
function initDatabase() {
    db.run(`
        CREATE TABLE IF NOT EXISTS access_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_code TEXT UNIQUE NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_used INTEGER DEFAULT 0,
            used_at DATETIME,
            used_by_ip TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Create a default admin key on first run
    db.get('SELECT * FROM access_keys WHERE is_admin = 1', (err, row) => {
        if (!row) {
            const adminKey = generateKey();
            db.run('INSERT INTO access_keys (key_code, is_admin) VALUES (?, 1)', [adminKey], (err) => {
                if (!err) {
                    console.log('===========================================');
                    console.log('🔑 ADMIN KEY CREATED:', adminKey);
                    console.log('===========================================');
                    console.log('Save this key! Use it to access /admin.html');
                    console.log('===========================================');
                }
            });
        }
    });
}

// Rate limiting (simple in-memory store)
const rateLimitStore = new Map();

function checkRateLimit(ip) {
    const now = Date.now();
    const attempts = rateLimitStore.get(ip) || [];
    
    // Remove attempts older than 15 minutes
    const recentAttempts = attempts.filter(timestamp => now - timestamp < 15 * 60 * 1000);
    
    if (recentAttempts.length >= 5) {
        return false; // Too many attempts
    }
    
    recentAttempts.push(now);
    rateLimitStore.set(ip, recentAttempts);
    return true;
}

// API: Validate key
app.post('/api/validate-key', (req, res) => {
    const { key } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress;

    // Rate limiting
    if (!checkRateLimit(clientIp)) {
        return res.status(429).json({ 
            valid: false, 
            error: 'Too many attempts. Please try again later.' 
        });
    }

    if (!key) {
        return res.status(400).json({ valid: false, error: 'Key is required' });
    }

    // Check if key exists and is not used
    db.get(
        'SELECT * FROM access_keys WHERE key_code = ? AND is_used = 0',
        [key.toUpperCase()],
        (err, row) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ valid: false, error: 'Server error' });
            }

            if (!row) {
                return res.status(401).json({ valid: false, error: 'Invalid or already used key' });
            }

            // Check if this is an admin key
            if (row.is_admin) {
                // Don't mark admin keys as used - they can be reused
                const token = jwt.sign(
                    { keyId: row.id, keyCode: row.key_code, isAdmin: true },
                    JWT_SECRET,
                    { expiresIn: '7d' }
                );

                return res.json({
                    valid: true,
                    token: token,
                    isAdmin: true,
                    message: 'Admin access granted',
                    redirectTo: '/admin.html'
                });
            }

            // Mark regular key as used
            db.run(
                'UPDATE access_keys SET is_used = 1, used_at = datetime("now"), used_by_ip = ? WHERE id = ?',
                [clientIp, row.id],
                (err) => {
                    if (err) {
                        console.error('Error marking key as used:', err);
                        return res.status(500).json({ valid: false, error: 'Server error' });
                    }

                    // Generate JWT token
                    const token = jwt.sign(
                        { keyId: row.id, keyCode: row.key_code, isAdmin: false },
                        JWT_SECRET,
                        { expiresIn: '7d' }
                    );

                    res.json({
                        valid: true,
                        token: token,
                        isAdmin: false,
                        message: 'Access granted',
                        redirectTo: '/games.html'
                    });
                }
            );
        }
    );
});

// API: Verify session token
app.get('/api/verify-session', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ valid: false });
    }

    const token = authHeader.substring(7);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ valid: true, keyId: decoded.keyId });
    } catch (err) {
        res.status(401).json({ valid: false, error: 'Invalid or expired token' });
    }
});

// API: Get games list (protected)
app.get('/api/games', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.substring(7);

    try {
        jwt.verify(token, JWT_SECRET);
        
        // Return list of games (replace with your actual games)
        res.json({
            games: [
                {
                    id: 1,
                    title: 'A Small World Cup',
                    url: '/games/a_small_world_cup.html',
                    description: 'A very goofy world cup.'
                },
                {
                    id: 2,
                    title: 'PolyTrack',
                    url: '/games/PolyTrack.html',
                    description: 'A simple racing game.'
                },
                {
                    id: 3,
                    title: 'Ragdoll Archers',
                    url: '/games/ragdoll_archers.html',
                    description: 'A fun archery game.'
                }
              
            ]
        });
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// Middleware to check admin access
function requireAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.substring(7);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded.isAdmin) {
            return res.status(403).json({ error: 'Admin access required' });
        }
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// ADMIN API: Generate new keys
app.post('/api/admin/keys/generate', requireAdmin, (req, res) => {
    const { count = 1, isAdmin = false } = req.body;
    const keys = [];

    for (let i = 0; i < Math.min(count, 100); i++) {
        const key = generateKey();
        keys.push(key);
        
        db.run('INSERT INTO access_keys (key_code, is_admin) VALUES (?, ?)', [key, isAdmin ? 1 : 0], (err) => {
            if (err) {
                console.error('Error inserting key:', err);
            }
        });
    }

    res.json({ keys, count: keys.length });
});

// ADMIN API: List all keys
app.get('/api/admin/keys', requireAdmin, (req, res) => {
    db.all('SELECT * FROM access_keys ORDER BY created_at DESC', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ keys: rows });
    });
});

// Helper: Generate random key
function generateKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = '';
    
    for (let i = 0; i < 16; i++) {
        if (i > 0 && i % 4 === 0) {
            key += '-';
        }
        key += chars[Math.floor(Math.random() * chars.length)];
    }
    
    return key;
}

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Visit http://localhost:${PORT} to test the key entry page');
});
