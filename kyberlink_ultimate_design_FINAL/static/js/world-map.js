/* ===================================
   KyberShield VPN - Interactive World Map
   Click-to-Connect Country Selection
   =================================== */

class KyberShieldWorldMap {
    constructor(containerId, dashboard) {
        this.container = document.getElementById(containerId);
        this.dashboard = dashboard;
        this.selectedCountry = null;
        this.servers = {};
        this.mapScale = 1;
        this.mapOffsetX = 0;
        this.mapOffsetY = 0;
        this.isDragging = false;
        
        this.init();
    }
    
    init() {
        this.createMapStructure();
        this.loadServerLocations();
        this.setupMapInteractions();
        this.setupResponsiveHandling();
        console.log('KyberShield World Map initialized');
    }
    
    createMapStructure() {
        this.container.innerHTML = `
            <div class="world-map-container">
                <div class="map-header">
                    <h3 class="map-title">
                        <i class="fas fa-globe"></i>
                        Choose Your Location
                    </h3>
                    <div class="map-controls">
                        <button class="map-control-btn" onclick="worldMap.resetView()" title="Reset View">
                            <i class="fas fa-home"></i>
                        </button>
                        <button class="map-control-btn" onclick="worldMap.toggleFullscreen()" title="Fullscreen">
                            <i class="fas fa-expand"></i>
                        </button>
                    </div>
                </div>
                
                <div class="map-viewport" id="map-viewport">
                    <svg class="world-map-svg" id="world-svg" viewBox="0 0 1000 500">
                        <!-- World map will be inserted here -->
                    </svg>
                    
                    <div class="map-tooltip" id="map-tooltip">
                        <div class="tooltip-content">
                            <div class="tooltip-country">Country</div>
                            <div class="tooltip-servers">Servers available</div>
                            <div class="tooltip-ping">Ping: --ms</div>
                        </div>
                    </div>
                </div>
                
                <div class="map-legend">
                    <div class="legend-item">
                        <div class="legend-dot available"></div>
                        <span>Available Servers</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-dot connected"></div>
                        <span>Connected</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-dot unavailable"></div>
                        <span>Coming Soon</span>
                    </div>
                </div>
            </div>
        `;
        
        this.svg = document.getElementById('world-svg');
        this.tooltip = document.getElementById('map-tooltip');
        this.viewport = document.getElementById('map-viewport');
        
        this.createWorldMapSVG();
    }
    
    createWorldMapSVG() {
        // Simplified world map with major countries/regions
        const worldPaths = {
            // North America
            'united-states': 'M 150 200 L 300 200 L 300 280 L 150 280 Z',
            'canada': 'M 150 150 L 300 150 L 300 200 L 150 200 Z',
            'mexico': 'M 150 280 L 250 280 L 250 320 L 150 320 Z',
            
            // Europe
            'united-kingdom': 'M 450 180 L 480 180 L 480 200 L 450 200 Z',
            'germany': 'M 500 180 L 530 180 L 530 210 L 500 210 Z',
            'france': 'M 480 200 L 510 200 L 510 230 L 480 230 Z',
            'netherlands': 'M 500 170 L 520 170 L 520 185 L 500 185 Z',
            'sweden': 'M 520 140 L 540 140 L 540 180 L 520 180 Z',
            'switzerland': 'M 500 210 L 520 210 L 520 225 L 500 225 Z',
            
            // Asia Pacific
            'japan': 'M 800 220 L 830 220 L 830 250 L 800 250 Z',
            'singapore': 'M 720 280 L 735 280 L 735 290 L 720 290 Z',
            'australia': 'M 750 350 L 820 350 L 820 400 L 750 400 Z',
            'south-korea': 'M 790 200 L 810 200 L 810 220 L 790 220 Z',
            'hong-kong': 'M 760 250 L 775 250 L 775 265 L 760 265 Z',
            'india': 'M 650 250 L 700 250 L 700 300 L 650 300 Z',
            
            // Others
            'brazil': 'M 300 350 L 380 350 L 380 420 L 300 420 Z',
            'south-africa': 'M 520 380 L 570 380 L 570 420 L 520 420 Z'
        };
        
        const serverCountries = {
            'united-states': { name: 'United States', servers: ['New York', 'Los Angeles', 'Chicago'], ping: 23, flag: '🇺🇸' },
            'united-kingdom': { name: 'United Kingdom', servers: ['London'], ping: 45, flag: '🇬🇧' },
            'germany': { name: 'Germany', servers: ['Frankfurt', 'Berlin'], ping: 56, flag: '🇩🇪' },
            'japan': { name: 'Japan', servers: ['Tokyo'], ping: 67, flag: '🇯🇵' },
            'singapore': { name: 'Singapore', servers: ['Singapore'], ping: 34, flag: '🇸🇬' },
            'australia': { name: 'Australia', servers: ['Sydney', 'Melbourne'], ping: 89, flag: '🇦🇺' },
            'canada': { name: 'Canada', servers: ['Toronto', 'Vancouver'], ping: 78, flag: '🇨🇦' },
            'sweden': { name: 'Sweden', servers: ['Stockholm'], ping: 112, flag: '🇸🇪' },
            'netherlands': { name: 'Netherlands', servers: ['Amsterdam'], ping: 42, flag: '🇳🇱' },
            'france': { name: 'France', servers: ['Paris'], ping: 51, flag: '🇫🇷' },
            'switzerland': { name: 'Switzerland', servers: ['Zurich'], ping: 48, flag: '🇨🇭' },
            'brazil': { name: 'Brazil', servers: ['São Paulo'], ping: 98, flag: '🇧🇷' },
            'south-korea': { name: 'South Korea', servers: ['Seoul'], ping: 72, flag: '🇰🇷' },
            'hong-kong': { name: 'Hong Kong', servers: ['Hong Kong'], ping: 65, flag: '🇭🇰' },
            'india': { name: 'India', servers: ['Mumbai'], ping: 85, flag: '🇮🇳' },
            'south-africa': { name: 'South Africa', servers: ['Cape Town'], ping: 125, flag: '🇿🇦' }
        };
        
        // Create country paths
        Object.entries(worldPaths).forEach(([countryId, path]) => {
            const countryElement = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            countryElement.setAttribute('d', path);
            countryElement.setAttribute('class', 'country');
            countryElement.setAttribute('data-country', countryId);
            countryElement.setAttribute('id', `country-${countryId}`);
            
            // Add server availability class
            if (serverCountries[countryId]) {
                countryElement.classList.add('has-servers');
                this.servers[countryId] = serverCountries[countryId];
            } else {
                countryElement.classList.add('no-servers');
            }
            
            this.svg.appendChild(countryElement);
        });
        
        // Create server markers
        Object.entries(serverCountries).forEach(([countryId, data]) => {
            const path = worldPaths[countryId];
            const coords = this.getPathCenter(path);
            
            const marker = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            marker.setAttribute('cx', coords.x);
            marker.setAttribute('cy', coords.y);
            marker.setAttribute('r', '6');
            marker.setAttribute('class', 'server-marker');
            marker.setAttribute('data-country', countryId);
            marker.setAttribute('id', `marker-${countryId}`);
            
            this.svg.appendChild(marker);
        });
    }
    
    getPathCenter(pathString) {
        // Simple approximation - get center of path bounding box
        const coords = pathString.match(/\d+/g);
        if (coords && coords.length >= 4) {
            const x1 = parseInt(coords[0]);
            const y1 = parseInt(coords[1]);
            const x2 = parseInt(coords[2]);
            const y2 = parseInt(coords[3]);
            return {
                x: (x1 + x2) / 2,
                y: (y1 + y2) / 2
            };
        }
        return { x: 0, y: 0 };
    }
    
    loadServerLocations() {
        // Update server markers based on current connection status
        Object.keys(this.servers).forEach(countryId => {
            const marker = document.getElementById(`marker-${countryId}`);
            if (marker) {
                marker.classList.add('available');
            }
        });
    }
    
    setupMapInteractions() {
        // Country hover/click interactions
        this.svg.addEventListener('mouseover', (e) => {
            const country = e.target.closest('.country, .server-marker');
            if (country && country.dataset.country) {
                this.showTooltip(e, country.dataset.country);
                country.classList.add('hovered');
                kyberAudio.playSound('hover', 0.2);
            }
        });
        
        this.svg.addEventListener('mouseout', (e) => {
            const country = e.target.closest('.country, .server-marker');
            if (country) {
                this.hideTooltip();
                country.classList.remove('hovered');
            }
        });
        
        this.svg.addEventListener('mousemove', (e) => {
            const country = e.target.closest('.country, .server-marker');
            if (country && this.tooltip.style.display === 'block') {
                this.updateTooltipPosition(e);
            }
        });
        
        this.svg.addEventListener('click', (e) => {
            const country = e.target.closest('.country, .server-marker');
            if (country && country.dataset.country) {
                this.selectCountry(country.dataset.country);
            }
        });
        
        // Pan and zoom
        this.setupPanZoom();
    }
    
    setupPanZoom() {
        let startX, startY, initialX, initialY;
        
        this.viewport.addEventListener('mousedown', (e) => {
            if (e.target === this.viewport || e.target === this.svg) {
                this.isDragging = true;
                startX = e.clientX;
                startY = e.clientY;
                initialX = this.mapOffsetX;
                initialY = this.mapOffsetY;
                this.viewport.style.cursor = 'grabbing';
            }
        });
        
        this.viewport.addEventListener('mousemove', (e) => {
            if (this.isDragging) {
                const deltaX = e.clientX - startX;
                const deltaY = e.clientY - startY;
                this.mapOffsetX = initialX + deltaX;
                this.mapOffsetY = initialY + deltaY;
                this.updateMapTransform();
            }
        });
        
        this.viewport.addEventListener('mouseup', () => {
            this.isDragging = false;
            this.viewport.style.cursor = 'grab';
        });
        
        this.viewport.addEventListener('wheel', (e) => {
            e.preventDefault();
            const delta = e.deltaY > 0 ? 0.9 : 1.1;
            const newScale = Math.max(0.5, Math.min(3, this.mapScale * delta));
            
            if (newScale !== this.mapScale) {
                this.mapScale = newScale;
                this.updateMapTransform();
            }
        });
    }
    
    updateMapTransform() {
        this.svg.style.transform = `translate(${this.mapOffsetX}px, ${this.mapOffsetY}px) scale(${this.mapScale})`;
    }
    
    showTooltip(event, countryId) {
        const serverData = this.servers[countryId];
        if (!serverData) return;
        
        const tooltip = this.tooltip;
        tooltip.querySelector('.tooltip-country').textContent = `${serverData.flag} ${serverData.name}`;
        tooltip.querySelector('.tooltip-servers').textContent = `${serverData.servers.length} server(s) available`;
        tooltip.querySelector('.tooltip-ping').textContent = `Ping: ${serverData.ping}ms`;
        
        tooltip.style.display = 'block';
        this.updateTooltipPosition(event);
    }
    
    updateTooltipPosition(event) {
        const tooltip = this.tooltip;
        const rect = this.viewport.getBoundingClientRect();
        const x = event.clientX - rect.left + 15;
        const y = event.clientY - rect.top - 10;
        
        tooltip.style.left = x + 'px';
        tooltip.style.top = y + 'px';
    }
    
    hideTooltip() {
        this.tooltip.style.display = 'none';
    }
    
    selectCountry(countryId) {
        const serverData = this.servers[countryId];
        if (!serverData) {
            this.dashboard.showNotification('No servers available in this location', 'info');
            return;
        }
        
        // Clear previous selection
        document.querySelectorAll('.country.selected, .server-marker.selected').forEach(el => {
            el.classList.remove('selected');
        });
        
        // Mark new selection
        const country = document.getElementById(`country-${countryId}`);
        const marker = document.getElementById(`marker-${countryId}`);
        
        if (country) country.classList.add('selected');
        if (marker) marker.classList.add('selected');
        
        this.selectedCountry = countryId;
        
        // Show connection modal/panel
        this.showConnectionModal(serverData, countryId);
        
        kyberAudio.playSound('click');
    }
    
    showConnectionModal(serverData, countryId) {
        const modal = document.createElement('div');
        modal.className = 'connection-modal';
        modal.innerHTML = `
            <div class="modal-overlay" onclick="this.parentElement.remove()"></div>
            <div class="modal-content">
                <div class="modal-header">
                    <h3>${serverData.flag} Connect to ${serverData.name}</h3>
                    <button class="modal-close" onclick="this.closest('.connection-modal').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                
                <div class="modal-body">
                    <div class="server-details">
                        <div class="detail-row">
                            <span class="detail-label">Available Servers:</span>
                            <span class="detail-value">${serverData.servers.length}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Average Ping:</span>
                            <span class="detail-value">${serverData.ping}ms</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Server Load:</span>
                            <span class="detail-value load-${this.getLoadLevel(serverData.ping)}">
                                ${this.getLoadText(serverData.ping)}
                            </span>
                        </div>
                    </div>
                    
                    <div class="server-list">
                        ${serverData.servers.map((server, index) => `
                            <div class="server-option" data-server="${server}" onclick="worldMap.connectToServer('${countryId}', '${server}')">
                                <div class="server-name">${server}</div>
                                <div class="server-ping">${serverData.ping + (index * 5)}ms</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                
                <div class="modal-footer">
                    <button class="btn-secondary" onclick="this.closest('.connection-modal').remove()">
                        Cancel
                    </button>
                    <button class="btn-primary" onclick="worldMap.connectToServer('${countryId}', '${serverData.servers[0]}')">
                        <i class="fas fa-bolt"></i>
                        Quick Connect
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Animate modal in
        setTimeout(() => {
            modal.classList.add('active');
        }, 10);
    }
    
    async connectToServer(countryId, serverName) {
        const modal = document.querySelector('.connection-modal');
        if (modal) modal.remove();
        
        const serverData = this.servers[countryId];
        
        // Update dashboard connection state
        this.dashboard.showNotification(`Connecting to ${serverName}, ${serverData.name}...`, 'info');
        
        try {
            // Simulate connection
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            // Update map visuals
            this.updateConnectionStatus(countryId, true);
            
            // Update dashboard
            if (this.dashboard.toggleConnection) {
                // Trigger dashboard connection if disconnected
                if (!this.dashboard.isConnected) {
                    await this.dashboard.toggleConnection();
                }
            }
            
            this.dashboard.showNotification(`Successfully connected to ${serverName}!`, 'success');
            kyberAudio.playSound('success');
            
            // Update dashboard location display
            const locationElement = document.getElementById('current-location');
            if (locationElement) {
                locationElement.textContent = serverData.name;
            }
            
        } catch (error) {
            this.dashboard.showNotification('Connection failed. Please try again.', 'error');
            kyberAudio.playSound('error');
        }
    }
    
    updateConnectionStatus(countryId, isConnected) {
        // Clear all connected states
        document.querySelectorAll('.server-marker.connected, .country.connected').forEach(el => {
            el.classList.remove('connected');
        });
        
        if (isConnected) {
            const country = document.getElementById(`country-${countryId}`);
            const marker = document.getElementById(`marker-${countryId}`);
            
            if (country) country.classList.add('connected');
            if (marker) marker.classList.add('connected');
        }
    }
    
    getLoadLevel(ping) {
        if (ping < 50) return 'low';
        if (ping < 100) return 'medium';
        return 'high';
    }
    
    getLoadText(ping) {
        if (ping < 50) return 'Low';
        if (ping < 100) return 'Medium';
        return 'High';
    }
    
    resetView() {
        this.mapScale = 1;
        this.mapOffsetX = 0;
        this.mapOffsetY = 0;
        this.updateMapTransform();
    }
    
    toggleFullscreen() {
        if (!document.fullscreenElement) {
            this.container.requestFullscreen();
        } else {
            document.exitFullscreen();
        }
    }
    
    setupResponsiveHandling() {
        const resizeObserver = new ResizeObserver(entries => {
            this.handleResize();
        });
        
        resizeObserver.observe(this.container);
    }
    
    handleResize() {
        // Adjust map scale and position for responsive design
        const containerRect = this.container.getBoundingClientRect();
        if (containerRect.width < 600) {
            // Mobile adjustments
            this.svg.style.minWidth = '600px';
        } else {
            this.svg.style.minWidth = '100%';
        }
    }
}

// Global instance will be created when dashboard initializes
let worldMap = null;