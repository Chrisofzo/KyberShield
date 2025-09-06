/* ===================================
   KyberShield VPN - Microinteractions & Animations
   Professional UI Enhancements
   =================================== */

class KyberShieldMicrointeractions {
    constructor() {
        this.animationsEnabled = localStorage.getItem('kybershield_animations_enabled') !== 'false';
        this.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        
        this.init();
    }
    
    init() {
        if (this.reducedMotion) {
            this.animationsEnabled = false;
        }
        
        this.setupButtonRipples();
        this.setupHoverEffects();
        this.setupScrollAnimations();
        this.setupFormInteractions();
        this.setupNotificationSystem();
        this.setupLoadingAnimations();
        this.setupParticleEffects();
        
        console.log('KyberShield Microinteractions initialized');
    }
    
    // Button Ripple Effect
    setupButtonRipples() {
        document.addEventListener('click', (e) => {
            if (!this.animationsEnabled) return;
            
            const button = e.target.closest('button, .auth-button, .cta-primary, .cta-secondary, .download-btn, .cyber-button');
            if (!button || button.disabled) return;
            
            this.createRipple(button, e);
            // Sound removed for silent interactions
        });
    }
    
    createRipple(element, event) {
        const rect = element.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;
        
        const ripple = document.createElement('div');
        ripple.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            background: radial-gradient(circle, rgba(255,255,255,0.6) 0%, transparent 70%);
            border-radius: 50%;
            pointer-events: none;
            transform: scale(0);
            animation: rippleEffect 0.6s ease-out;
            z-index: 1000;
        `;
        
        element.style.position = 'relative';
        element.style.overflow = 'hidden';
        element.appendChild(ripple);
        
        setTimeout(() => {
            if (ripple.parentNode) {
                ripple.parentNode.removeChild(ripple);
            }
        }, 600);
    }
    
    // Enhanced Hover Effects
    setupHoverEffects() {
        const hoverElements = document.querySelectorAll('.feature-card, .server-item, .stat-card, .nav-item, .server-card, .connection-card');
        
        hoverElements.forEach(element => {
            element.addEventListener('mouseenter', () => {
                if (!this.animationsEnabled) return;
                
                kyberAudio.playSound('hover', 0.3);
                this.addGlowEffect(element);
            });
            
            element.addEventListener('mouseleave', () => {
                this.removeGlowEffect(element);
            });
        });
    }
    
    addGlowEffect(element) {
        element.style.boxShadow = element.style.boxShadow + ', 0 0 20px rgba(0, 212, 255, 0.3)';
        element.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
    }
    
    removeGlowEffect(element) {
        element.style.boxShadow = element.style.boxShadow.replace(', 0 0 20px rgba(0, 212, 255, 0.3)', '');
    }
    
    // Scroll-based Animations
    setupScrollAnimations() {
        if (!this.animationsEnabled) return;
        
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };
        
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    this.animateElement(entry.target);
                }
            });
        }, observerOptions);
        
        // Observe elements for scroll animations
        const animateElements = document.querySelectorAll('.feature-card, .testimonial-card, .stat-card, .download-card');
        animateElements.forEach(element => {
            element.style.opacity = '0';
            element.style.transform = 'translateY(30px)';
            observer.observe(element);
        });
    }
    
    animateElement(element) {
        element.style.transition = 'all 0.6s cubic-bezier(0.4, 0, 0.2, 1)';
        element.style.opacity = '1';
        element.style.transform = 'translateY(0)';
    }
    
    // Form Input Enhancements
    setupFormInteractions() {
        const inputs = document.querySelectorAll('input, textarea');
        
        inputs.forEach(input => {
            input.addEventListener('focus', () => {
                this.animateInputFocus(input);
            });
            
            input.addEventListener('blur', () => {
                this.animateInputBlur(input);
            });
            
            input.addEventListener('input', () => {
                this.validateInputRealtime(input);
            });
        });
    }
    
    animateInputFocus(input) {
        if (!this.animationsEnabled) return;
        
        const parent = input.parentElement;
        const label = parent.querySelector('label');
        
        input.style.transform = 'scale(1.02)';
        input.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
        
        if (label) {
            label.style.color = '#00d4ff';
            label.style.transform = 'scale(0.95) translateY(-2px)';
            label.style.transition = 'all 0.3s ease';
        }
        
        kyberAudio.playSound('click', 0.2);
    }
    
    animateInputBlur(input) {
        input.style.transform = 'scale(1)';
        
        const parent = input.parentElement;
        const label = parent.querySelector('label');
        
        if (label && !input.value) {
            label.style.color = '';
            label.style.transform = '';
        }
    }
    
    validateInputRealtime(input) {
        if (input.type === 'email') {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            const isValid = emailRegex.test(input.value);
            
            input.style.borderColor = input.value ? (isValid ? '#10b981' : '#ef4444') : '';
        } else if (input.type === 'password') {
            const strength = this.calculatePasswordStrength(input.value);
            input.style.borderColor = strength > 2 ? '#10b981' : strength > 0 ? '#f59e0b' : '';
        }
    }
    
    calculatePasswordStrength(password) {
        let score = 0;
        if (password.length >= 8) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;
        return score;
    }
    
    // Enhanced Notification System
    setupNotificationSystem() {
        this.notificationContainer = document.createElement('div');
        this.notificationContainer.id = 'kyberlink-notifications';
        this.notificationContainer.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            pointer-events: none;
        `;
        document.body.appendChild(this.notificationContainer);
    }
    
    showNotification(message, type = 'info', duration = 4000) {
        const notification = document.createElement('div');
        const id = 'notification-' + Date.now();
        
        const colors = {
            success: 'linear-gradient(135deg, #10b981, #059669)',
            error: 'linear-gradient(135deg, #ef4444, #dc2626)',
            warning: 'linear-gradient(135deg, #f59e0b, #d97706)',
            info: 'linear-gradient(135deg, #00d4ff, #0ea5e9)'
        };
        
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-triangle',
            warning: 'fa-exclamation-circle',
            info: 'fa-info-circle'
        };
        
        notification.id = id;
        notification.style.cssText = `
            background: ${colors[type]};
            color: white;
            padding: 16px 20px;
            border-radius: 12px;
            margin-bottom: 10px;
            font-weight: 600;
            font-size: 14px;
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.3);
            transform: translateX(100%);
            opacity: 0;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            pointer-events: auto;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 10px;
            max-width: 350px;
        `;
        
        notification.innerHTML = `
            <i class="fas ${icons[type]}"></i>
            <span>${message}</span>
            <i class="fas fa-times" style="margin-left: auto; opacity: 0.7; cursor: pointer;"></i>
        `;
        
        this.notificationContainer.appendChild(notification);
        
        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
            notification.style.opacity = '1';
        }, 100);
        
        // Play sound
        kyberAudio.playSound(type === 'success' ? 'success' : type === 'error' ? 'error' : 'notification');
        
        // Auto remove
        const autoRemove = setTimeout(() => {
            this.removeNotification(id);
        }, duration);
        
        // Manual remove
        notification.addEventListener('click', () => {
            clearTimeout(autoRemove);
            this.removeNotification(id);
        });
        
        return id;
    }
    
    removeNotification(id) {
        const notification = document.getElementById(id);
        if (notification) {
            notification.style.transform = 'translateX(100%)';
            notification.style.opacity = '0';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 400);
        }
    }
    
    // Loading Animations
    setupLoadingAnimations() {
        this.createLoadingSpinner();
    }
    
    createLoadingSpinner() {
        const style = document.createElement('style');
        style.textContent = `
            .kyberlink-loading {
                display: inline-block;
                width: 20px;
                height: 20px;
                border: 2px solid rgba(255, 255, 255, 0.3);
                border-radius: 50%;
                border-top-color: #fff;
                animation: kyberSpinning 1s ease-in-out infinite;
            }
            
            @keyframes kyberSpinning {
                to { transform: rotate(360deg); }
            }
            
            .kyberlink-pulse {
                animation: kyberPulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
            }
            
            @keyframes kyberPulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
            
            .kyberlink-glow {
                animation: kyberGlow 3s ease-in-out infinite alternate;
            }
            
            @keyframes kyberGlow {
                from { box-shadow: 0 0 20px rgba(0, 212, 255, 0.5); }
                to { box-shadow: 0 0 30px rgba(0, 212, 255, 0.8), 0 0 40px rgba(139, 92, 246, 0.3); }
            }
        `;
        document.head.appendChild(style);
    }
    
    showLoading(element, text = 'Loading...') {
        const originalContent = element.innerHTML;
        element.setAttribute('data-original-content', originalContent);
        element.innerHTML = `<span class="kyberlink-loading"></span> ${text}`;
        element.disabled = true;
        
        return () => {
            element.innerHTML = originalContent;
            element.disabled = false;
            element.removeAttribute('data-original-content');
        };
    }
    
    // Particle Effects for Special Events
    setupParticleEffects() {
        this.particleContainer = document.createElement('div');
        this.particleContainer.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 9999;
        `;
        document.body.appendChild(this.particleContainer);
    }
    
    createConnectionParticles(element) {
        if (!this.animationsEnabled) return;
        
        const rect = element.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        
        for (let i = 0; i < 20; i++) {
            const particle = document.createElement('div');
            particle.style.cssText = `
                position: absolute;
                width: 4px;
                height: 4px;
                background: #00d4ff;
                border-radius: 50%;
                left: ${centerX}px;
                top: ${centerY}px;
                pointer-events: none;
                animation: particleExplode 1.5s ease-out forwards;
                animation-delay: ${i * 50}ms;
            `;
            
            const angle = (i / 20) * Math.PI * 2;
            const distance = 100 + Math.random() * 100;
            particle.style.setProperty('--end-x', Math.cos(angle) * distance + 'px');
            particle.style.setProperty('--end-y', Math.sin(angle) * distance + 'px');
            
            this.particleContainer.appendChild(particle);
            
            setTimeout(() => {
                if (particle.parentNode) {
                    particle.parentNode.removeChild(particle);
                }
            }, 1500);
        }
        
        // Add particle explosion animation
        if (!document.querySelector('#particle-animations')) {
            const style = document.createElement('style');
            style.id = 'particle-animations';
            style.textContent = `
                @keyframes particleExplode {
                    0% {
                        opacity: 1;
                        transform: translate(0, 0) scale(1);
                    }
                    100% {
                        opacity: 0;
                        transform: translate(var(--end-x), var(--end-y)) scale(0);
                    }
                }
            `;
            document.head.appendChild(style);
        }
    }
    
    // Typing Effect for Text
    typeText(element, text, speed = 50) {
        if (!this.animationsEnabled) {
            element.textContent = text;
            return;
        }
        
        element.textContent = '';
        let i = 0;
        
        const typeChar = () => {
            if (i < text.length) {
                element.textContent += text.charAt(i);
                i++;
                setTimeout(typeChar, speed);
            }
        };
        
        typeChar();
    }
    
    // Counter Animation
    animateCounter(element, target, duration = 2000) {
        if (!this.animationsEnabled) {
            element.textContent = target;
            return;
        }
        
        const start = parseInt(element.textContent) || 0;
        const increment = (target - start) / (duration / 16);
        let current = start;
        
        const updateCounter = () => {
            current += increment;
            element.textContent = Math.round(current);
            
            if (Math.abs(current - target) > Math.abs(increment)) {
                requestAnimationFrame(updateCounter);
            } else {
                element.textContent = target;
            }
        };
        
        updateCounter();
    }
    
    // Settings
    setAnimationsEnabled(enabled) {
        this.animationsEnabled = enabled && !this.reducedMotion;
        localStorage.setItem('kyberlink_animations_enabled', enabled.toString());
    }
    
    isAnimationsEnabled() {
        return this.animationsEnabled;
    }
}

// Global Microinteractions Instance
const kyberInteractions = new KyberLinkMicrointeractions();

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = KyberLinkMicrointeractions;
}