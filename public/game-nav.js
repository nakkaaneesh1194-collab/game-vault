// game-nav.js - Universal navigation bar for all games
(function() {
    // Get game title from page title or default
    const gameTitle = document.title || 'Game';

    // Create nav bar HTML
    const navBar = document.createElement('div');
    navBar.className = 'game-nav-bar';
    navBar.innerHTML = `
        <div class="game-nav-title">🎮 ${gameTitle}</div>
        <a href="/games.html" class="game-nav-back">← Back to Games</a>
    `;

    // Create style element
    const style = document.createElement('style');
    style.textContent = `
        .game-nav-bar {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 50px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            z-index: 999999;
        }

        .game-nav-title {
            color: white;
            font-size: 18px;
            font-weight: bold;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        .game-nav-back {
            background: rgba(255, 255, 255, 0.2);
            border: 2px solid white;
            color: white;
            padding: 8px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            text-decoration: none;
            transition: background 0.3s;
        }

        .game-nav-back:hover {
            background: rgba(255, 255, 255, 0.3);
        }

        body {
            padding-top: 50px !important;
        }
    `;

    // Add to page when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            document.head.appendChild(style);
            document.body.insertBefore(navBar, document.body.firstChild);
        });
    } else {
        document.head.appendChild(style);
        document.body.insertBefore(navBar, document.body.firstChild);
    }
})();
