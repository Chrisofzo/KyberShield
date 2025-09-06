/* ===============================================
   KyberShield VPN - SPA Router System
   Multi-page navigation without full refresh
   =============================================== */

class KyberShieldRouter {
    constructor() {
        this.routes = {
            '/': 'landing',
            '/download': 'download', 
            '/compare': 'compare',
            '/login': 'login',
            '/register': 'register',
            '/dashboard': 'dashboard'
        };
        
        this.currentRoute = '/';
        this.init();
    }
    
    init() {
        // Handle browser back/forward
        window.addEventListener('popstate', (e) => {
            this.handleRoute(window.location.pathname, false);
        });
        
        // Handle navbar clicks
        this.setupNavigation();
        
        // Load initial route
        this.handleRoute(window.location.pathname || '/', true);
    }
    
    setupNavigation() {
        document.addEventListener('click', (e) => {
            const link = e.target.closest('a[href^="/"]');
            if (link && !link.hasAttribute('target')) {
                e.preventDefault();
                const path = link.getAttribute('href');
                this.navigate(path);
            }
        });
    }
    
    navigate(path) {
        if (path !== this.currentRoute) {
            history.pushState(null, '', path);
            this.handleRoute(path, true);
        }
    }
    
    async handleRoute(path, updateHistory = true) {
        // Normalize path
        if (path === '' || path === '/') {
            path = '/';
        }
        
        const routeName = this.routes[path];
        if (!routeName) {
            // 404 - redirect to home
            this.navigate('/');
            return;
        }
        
        this.currentRoute = path;
        
        // Update navbar active state
        this.updateNavbar(path);
        
        // Load page content
        await this.loadPage(routeName);
        
        // Scroll to top
        window.scrollTo(0, 0);
    }
    
    updateNavbar(currentPath) {
        // Remove active class from all nav links
        document.querySelectorAll('.nav-menu a').forEach(link => {
            link.classList.remove('active');
        });
        
        // Add active class to current page - handle both exact match and homepage
        if (currentPath === '/' || currentPath === '') {
            const homeLink = document.querySelector('.nav-menu a[href="/"]');
            if (homeLink) {
                homeLink.classList.add('active');
            }
        } else {
            const activeLink = document.querySelector(`.nav-menu a[href="${currentPath}"]`);
            if (activeLink) {
                activeLink.classList.add('active');
            }
        }
    }
    
    async loadPage(routeName) {
        const contentContainer = document.getElementById('page-content');
        if (!contentContainer) return;
        
        // Show loading
        contentContainer.innerHTML = '<div class="page-loading">Loading...</div>';
        
        try {
            // Fetch page content with timeout and retry
            const response = await this.fetchWithRetry(`/api/page/${routeName}`, 3);
            
            if (response.status === 401) {
                // Authentication required - redirect to login
                console.log('Authentication required, redirecting to login...');
                this.navigate('/login');
                return;
            }
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const html = await response.text();
            
            // Update content with fade effect
            contentContainer.style.opacity = '0';
            setTimeout(() => {
                contentContainer.innerHTML = html;
                contentContainer.style.opacity = '1';
                
                // Initialize page-specific JavaScript
                this.initializePage(routeName);
            }, 150);
            
        } catch (error) {
            console.error('Error loading page:', error);
            contentContainer.innerHTML = `
                <div class="page-error">
                    <h3>Connection Error</h3>
                    <p>Unable to load page content. <button onclick="location.reload()">Retry</button></p>
                </div>
            `;
        }
    }
    
    async fetchWithRetry(url, retries = 3) {
        for (let i = 0; i < retries; i++) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
                
                const response = await fetch(url, {
                    signal: controller.signal,
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    cache: 'no-cache'
                });
                
                clearTimeout(timeoutId);
                return response;
                
            } catch (error) {
                console.warn(`Fetch attempt ${i + 1} failed:`, error.message);
                if (i === retries - 1) throw error;
                await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, i))); // Exponential backoff
            }
        }
    }

    initializePage(routeName) {
        // Execute any script tags in the loaded content
        const scripts = document.querySelectorAll('#page-content script');
        scripts.forEach(script => {
            const newScript = document.createElement('script');
            newScript.textContent = script.textContent;
            document.body.appendChild(newScript);
            document.body.removeChild(newScript);
        });
        
        switch (routeName) {
            case 'dashboard':
                // Initialize dashboard if needed
                if (window.initDashboard) {
                    setTimeout(() => window.initDashboard(), 100);
                }
                break;
            case 'login':
                // Initialize login form handlers
                setTimeout(() => {
                    if (window.KyberShieldAuth) {
                        window.KyberShieldAuth.initLoginForm();
                    } else {
                        console.error('KyberShieldAuth not available for login');
                    }
                }, 100);
                break;
            case 'register':
                // Initialize register form handlers
                setTimeout(() => {
                    if (window.KyberShieldAuth) {
                        window.KyberShieldAuth.initRegisterForm();
                    } else {
                        console.error('KyberShieldAuth not available for register');
                    }
                }, 100);
                break;
            case 'download':
                // Initialize download page if needed
                break;
            case 'compare':
                // Initialize comparison animations if needed
                break;
        }
    }
}

// Connection monitor for stability
class ConnectionMonitor {
    constructor() {
        this.isOnline = navigator.onLine;
        this.setupEventListeners();
        this.startHeartbeat();
    }
    
    setupEventListeners() {
        window.addEventListener('online', () => {
            this.isOnline = true;
            console.log('Connection restored');
            if (window.kyberShieldRouter) {
                window.kyberShieldRouter.handleRoute(window.location.pathname, false);
            }
        });
        
        window.addEventListener('offline', () => {
            this.isOnline = false;
            console.log('Connection lost');
        });
    }
    
    startHeartbeat() {
        setInterval(async () => {
            if (this.isOnline) {
                try {
                    await fetch('/api/health', { 
                        method: 'HEAD',
                        cache: 'no-cache',
                        signal: AbortSignal.timeout(5000)
                    });
                } catch (error) {
                    console.warn('Heartbeat failed:', error.message);
                }
            }
        }, 30000); // Check every 30 seconds
    }
}

// Initialize router and connection monitor when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.kyberShieldRouter = new KyberShieldRouter();
    window.connectionMonitor = new ConnectionMonitor();
});