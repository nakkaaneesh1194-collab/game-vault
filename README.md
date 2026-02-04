# Game Vault - Whitelist Key Protected Website

A secure website that requires users to enter a one-time whitelist key before accessing your game collection.

## 🔒 Security Features

- Keys are stored server-side only (never exposed to browser)
- Each key can only be used once
- Session-based authentication with JWT tokens
- Rate limiting to prevent brute force attempts
- Protected game files

## 📁 Project Structure

```
game-vault/
├── server.js              # Backend API server
├── package.json           # Node.js dependencies
├── public/
│   ├── index.html        # Key entry landing page (blocks all access)
│   ├── games.html        # Games library (only accessible after key validation)
│   └── games/            # Your game files go here
│       ├── game1.html
│       ├── game2.html
│       └── ...
├── keys.db               # SQLite database (created automatically)
└── README.md
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Start the Server

```bash
npm start
```

The server will run on `http://localhost:3000`

### 3. Create Your First Keys

Open another terminal and generate keys using curl:

```bash
curl -X POST http://localhost:3000/api/admin/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"count": 5}'
```

This will generate 5 keys you can distribute to users.

### 4. Test It Out

1. Visit `http://localhost:3000`
2. You'll see the key entry page - no way to bypass it!
3. Enter one of the generated keys
4. After successful validation, you'll be redirected to the games page

## 📂 Folder Setup

Create a `public` folder and move your HTML files:

```bash
mkdir -p public/games
mv index.html public/
mv games.html public/
```

Add your game files to `public/games/`:
- `public/games/game1.html`
- `public/games/game2.html`
- etc.

## 🎮 Adding Games

Edit `server.js` and update the games array in the `/api/games` endpoint:

```javascript
res.json({
    games: [
        { 
            id: 1, 
            title: 'My Awesome Game', 
            url: '/games/game1.html', 
            thumbnail: '/images/game1.png',
            description: 'A fun platformer game'
        },
        // Add more games...
    ]
});
```

## 🔑 Managing Keys

### Generate Keys (via API)

```bash
# Generate 10 keys
curl -X POST http://localhost:3000/api/admin/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"count": 10}'
```

### View All Keys (via API)

```bash
curl http://localhost:3000/api/admin/keys
```

### Direct Database Access

```bash
sqlite3 keys.db

# View all keys
SELECT * FROM access_keys;

# View unused keys
SELECT * FROM access_keys WHERE is_used = 0;

# Manually add a key
INSERT INTO access_keys (key_code) VALUES ('ABCD-EFGH-IJKL-MNOP');
```

## 🛡️ Security Recommendations

### Before Deploying:

1. **Change JWT Secret**
   ```bash
   # Set environment variable
   export JWT_SECRET="your-long-random-secret-key-here"
   ```

2. **Add Admin Authentication**
   - Currently admin endpoints are unprotected
   - Add password/login for `/api/admin/*` endpoints

3. **Enable HTTPS**
   - Use SSL certificate (Let's Encrypt is free)
   - Never run in production without HTTPS

4. **Set Rate Limits**
   - Already implemented: 5 attempts per 15 minutes per IP
   - Adjust in `server.js` if needed

## 🌐 Deployment

### Option 1: Render (Free)

1. Push code to GitHub
2. Go to render.com
3. Create new "Web Service"
4. Connect your repo
5. Set environment variables:
   - `JWT_SECRET`: random secret key
6. Deploy!

### Option 2: Railway (Free)

1. Push code to GitHub
2. Go to railway.app
3. "New Project" → "Deploy from GitHub"
4. Add environment variable `JWT_SECRET`
5. Deploy!

### Option 3: Your Own Server

```bash
# Install Node.js on your server
# Clone your repo
git clone your-repo-url
cd game-vault

# Install dependencies
npm install

# Run with PM2 (keeps it running)
npm install -g pm2
pm2 start server.js
pm2 save
```

## 📊 Database Schema

```sql
-- Access keys table
CREATE TABLE access_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_code TEXT UNIQUE NOT NULL,
    is_used INTEGER DEFAULT 0,
    used_at DATETIME,
    used_by_ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## 🐛 Troubleshooting

**"Cannot find module 'express'"**
- Run `npm install`

**Keys not working**
- Check database: `sqlite3 keys.db "SELECT * FROM access_keys;"`
- Make sure key hasn't been used already

**Can't access games page directly**
- This is intentional! Must enter valid key first
- Check browser console for errors

**Rate limit triggered**
- Wait 15 minutes or restart server (clears in-memory rate limits)

## 📝 License

MIT
