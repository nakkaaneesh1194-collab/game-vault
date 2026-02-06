// server.js - Node.js backend with PostgreSQL for key validation
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3030;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';
const DATABASE_URL = process.env.DATABASE_URL;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static('public')); // Serve static files (index.html, games.html, etc.)

// Initialize PostgreSQL connection
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Test connection and create tables
pool.connect((err, client, release) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Connected to PostgreSQL database');
        release();
        initDatabase();
    }
});

// Create tables if they don't exist
async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS access_keys (
                id SERIAL PRIMARY KEY,
                key_code VARCHAR(255) UNIQUE NOT NULL,
                is_admin INTEGER DEFAULT 0,
                is_used INTEGER DEFAULT 0,
                is_revoked INTEGER DEFAULT 0,
                used_at TIMESTAMP,
                used_by_ip VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Create a default admin key on first run
        const result = await pool.query('SELECT * FROM access_keys WHERE is_admin = 1');
        
        if (result.rows.length === 0) {
            const adminKey = generateKey();
            await pool.query('INSERT INTO access_keys (key_code, is_admin) VALUES ($1, 1)', [adminKey]);
            
            console.log('===========================================');
            console.log('🔑 ADMIN KEY CREATED:', adminKey);
            console.log('===========================================');
            console.log('Save this key! Use it to access /admin.html');
            console.log('===========================================');
        }
    } catch (err) {
        console.error('Error initializing database:', err);
    }
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
app.post('/api/validate-key', async (req, res) => {
    const { key } = req.body;
    let clientIp = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
    
    // Clean up IPv6 localhost to IPv4
    if (clientIp === '::1' || clientIp === '::ffff:127.0.0.1') {
        clientIp = '127.0.0.1';
    }
    
    // Extract real IP from x-forwarded-for if behind proxy
    if (clientIp && clientIp.includes(',')) {
        clientIp = clientIp.split(',')[0].trim();
    }

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

    try {
        // Check if key exists and is not revoked
        const result = await pool.query(
            'SELECT * FROM access_keys WHERE key_code = $1 AND is_revoked = 0',
            [key.toUpperCase()]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ valid: false, error: 'Invalid or revoked key' });
        }

        const row = result.rows[0];

        // Check if this is an admin key
        if (row.is_admin) {
            // Track admin key usage but don't mark as used
            await pool.query(
                'UPDATE access_keys SET used_at = NOW(), used_by_ip = $1 WHERE id = $2',
                [clientIp, row.id]
            );
            
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

        // For regular keys, check if already used
        if (row.is_used) {
            return res.status(401).json({ valid: false, error: 'Key has already been used' });
        }

        // Mark regular key as used
        await pool.query(
            'UPDATE access_keys SET is_used = 1, used_at = NOW(), used_by_ip = $1 WHERE id = $2',
            [clientIp, row.id]
        );

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
    } catch (err) {
        console.error('Database error:', err);
        res.status(500).json({ valid: false, error: 'Server error' });
    }
});

// API: Verify session token
app.get('/api/verify-session', async (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ valid: false });
    }

    const token = authHeader.substring(7);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Check if the key has been revoked
        const result = await pool.query(
            'SELECT is_revoked, is_admin FROM access_keys WHERE id = $1',
            [decoded.keyId]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ valid: false, error: 'Key not found' });
        }
        
        const key = result.rows[0];
        
        // If key is revoked and not an admin key, deny access
        if (key.is_revoked && !key.is_admin) {
            return res.status(401).json({ valid: false, error: 'Access revoked' });
        }
        
        res.json({ valid: true, keyId: decoded.keyId });
    } catch (err) {
        res.status(401).json({ valid: false, error: 'Invalid or expired token' });
    }
});

// API: Get games list (protected)
app.get('/api/games', async (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.substring(7);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Check if the key has been revoked
        const result = await pool.query(
            'SELECT is_revoked, is_admin FROM access_keys WHERE id = $1',
            [decoded.keyId]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Key not found' });
        }
        
        const key = result.rows[0];
        
        // If key is revoked and not an admin key, deny access
        if (key.is_revoked && !key.is_admin) {
            return res.status(401).json({ error: 'Access has been revoked' });
        }
        
        // Return list of games (replace with your actual games)
        res.json({
            games: [
                { id: 1, title: 'A Small World Cup', url: '/games/a_small_world_cup.html', description: 'Fun soccer game!' },
                { id: 2, title: 'PolyTrack', url: '/games/PolyTrack.html', description: 'Racing game' }
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
app.post('/api/admin/keys/generate', requireAdmin, async (req, res) => {
    const { count = 1, isAdmin = false } = req.body;
    const keys = [];

    try {
        for (let i = 0; i < Math.min(count, 100); i++) {
            const key = generateKey();
            keys.push(key);
            
            await pool.query(
                'INSERT INTO access_keys (key_code, is_admin) VALUES ($1, $2)',
                [key, isAdmin ? 1 : 0]
            );
        }

        res.json({ keys, count: keys.length });
    } catch (err) {
        console.error('Error generating keys:', err);
        res.status(500).json({ error: 'Error generating keys' });
    }
});

// ADMIN API: List all keys
app.get('/api/admin/keys', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM access_keys ORDER BY created_at DESC');
        res.json({ keys: result.rows });
    } catch (err) {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// ADMIN API: Revoke a key (mark as revoked - blocks access)
app.post('/api/admin/keys/revoke/:id', requireAdmin, async (req, res) => {
    const keyId = req.params.id;
    
    try {
        const result = await pool.query(
            'UPDATE access_keys SET is_revoked = 1 WHERE id = $1 AND is_admin = 0 RETURNING *',
            [keyId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Key not found or is an admin key' });
        }
        
        res.json({ success: true, message: 'Key revoked successfully' });
    } catch (err) {
        console.error('Error revoking key:', err);
        res.status(500).json({ error: 'Error revoking key' });
    }
});

// ADMIN API: Unrevoke a key (restore access)
app.post('/api/admin/keys/unrevoke/:id', requireAdmin, async (req, res) => {
    const keyId = req.params.id;
    
    try {
        const result = await pool.query(
            'UPDATE access_keys SET is_revoked = 0 WHERE id = $1 AND is_admin = 0 RETURNING *',
            [keyId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Key not found or is an admin key' });
        }
        
        res.json({ success: true, message: 'Key access restored' });
    } catch (err) {
        console.error('Error unrevoking key:', err);
        res.status(500).json({ error: 'Error unrevoking key' });
    }
});

// ADMIN API: Delete a key permanently
app.delete('/api/admin/keys/:id', requireAdmin, async (req, res) => {
    const keyId = req.params.id;
    
    try {
        const result = await pool.query(
            'DELETE FROM access_keys WHERE id = $1 AND is_admin = 0 RETURNING *',
            [keyId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Key not found or is an admin key' });
        }
        
        res.json({ success: true, message: 'Key deleted successfully' });
    } catch (err) {
        console.error('Error deleting key:', err);
        res.status(500).json({ error: 'Error deleting key' });
    }
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
