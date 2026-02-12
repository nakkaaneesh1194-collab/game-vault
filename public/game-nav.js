// game-nav.js - Universal navigation bar for all games
(function() {
    // Prevent games from registering service workers (causes 404 errors)
    if ('serviceWorker' in navigator) {
        const originalRegister = navigator.serviceWorker.register;
        navigator.serviceWorker.register = function(scriptURL, options) {
            // Only allow our Buckshot Roulette service worker
            if (scriptURL.includes('buckshotroulette')) {
                return originalRegister.call(navigator.serviceWorker, scriptURL, options);
            }
            // Block all other service worker registrations
            console.log('Blocked service worker registration:', scriptURL);
            return Promise.resolve({ scope: options?.scope || '/' });
        };
    }

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
            position: fixed !important;
            top: 0 !important;
            left: 0 !important;
            right: 0 !important;
            height: 50px !important;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
            display: flex !important;
            align-items: center !important;
            justify-content: space-between !important;
            padding: 0 20px !important;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3) !important;
            z-index: 999999 !important;
            box-sizing: border-box !important;
        }

        .game-nav-title {
            color: white !important;
            font-size: 18px !important;
            font-weight: bold !important;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif !important;
        }

        .game-nav-back {
            background: rgba(255, 255, 255, 0.2) !important;
            border: 2px solid white !important;
            color: white !important;
            padding: 8px 20px !important;
            border-radius: 6px !important;
            cursor: pointer !important;
            font-size: 14px !important;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif !important;
            text-decoration: none !important;
            transition: background 0.3s !important;
        }

        .game-nav-back:hover {
            background: rgba(255, 255, 255, 0.3) !important;
        }

        /* Adjust game content - use viewport height minus nav bar */
        html, body {
            margin: 0 !important;
            padding: 0 !important;
            overflow: hidden !important;
            height: 100vh !important;
        }

        body > *:not(.game-nav-bar) {
            margin-top: 50px !important;
            height: calc(100vh - 50px) !important;
            max-height: calc(100vh - 50px) !important;
        }

        /* Special case for canvas elements */
        canvas {
            max-height: calc(100vh - 50px) !important;
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
