// Authentication handlers for KyberShield VPN

// Utility function for password visibility toggle
function togglePassword() {
    const passwordInput = document.getElementById('password');
    const showIcon = document.getElementById('showIcon');
    
    if (passwordInput && showIcon) {
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            showIcon.textContent = '🙈';
        } else {
            passwordInput.type = 'password';
            showIcon.textContent = '👁️';
        }
    }
}

// Make togglePassword globally available
window.togglePassword = togglePassword;

const KyberShieldAuth = {
    // Initialize login form
    initLoginForm() {
        console.log('=== KyberShield Auth: Initializing login form handlers ===');
        const loginForm = document.getElementById('loginForm');
        
        if (!loginForm) {
            console.error('=== ERROR: Login form not found! ===');
            console.log('Available forms:', document.querySelectorAll('form'));
            return;
        }
        
        console.log('=== SUCCESS: Login form found ===', loginForm);
        
        // Don't auto-redirect on login page - let user login normally
        // this.checkAuthAndRedirect();
        
        console.log('=== Adding submit event listener to form ===');
        
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            console.log('=== FORM SUBMITTED! ===');
            console.log('Event:', e);
            console.log('Email value:', document.getElementById('email')?.value);
            console.log('Password value:', document.getElementById('password')?.value ? '[HIDDEN]' : 'EMPTY');
            
            const submitBtn = document.getElementById('submitBtn');
            const originalText = submitBtn.textContent;
            const errorElement = document.getElementById('errorMessage');
            
            // Clear previous errors
            if (errorElement) {
                errorElement.style.display = 'none';
            }
            
            // Show loading state
            submitBtn.disabled = true;
            submitBtn.textContent = 'Signing in...';
            
            // Get form data
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'include',
                    body: JSON.stringify({ email, password })
                });
                
                console.log('Login response status:', response.status);
                const result = await response.json();
                
                if (response.status === 200 && result.success) {
                    submitBtn.textContent = 'Success! Redirecting...';
                    console.log('Login successful, redirecting to dashboard...');
                    
                    // Use SPA router to navigate to dashboard
                    setTimeout(() => {
                        if (window.kyberShieldRouter) {
                            window.kyberShieldRouter.navigate('/dashboard');
                        } else {
                            window.location.href = '/dashboard';
                        }
                    }, 500);
                } else if (response.status === 401) {
                    // Show error message under the login form on 401
                    const errorMsg = 'Invalid email or password';
                    
                    if (errorElement) {
                        errorElement.textContent = errorMsg;
                        errorElement.style.display = 'block';
                    }
                    
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalText;
                } else {
                    // Handle other errors
                    const errorMsg = result.error || 'Login failed';
                    
                    if (errorElement) {
                        errorElement.textContent = errorMsg;
                        errorElement.style.display = 'block';
                    }
                    
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalText;
                }
            } catch (error) {
                console.error('Login error:', error);
                
                if (errorElement) {
                    errorElement.textContent = 'Connection error. Please try again.';
                    errorElement.style.display = 'block';
                }
                
                submitBtn.disabled = false;
                submitBtn.textContent = originalText;
            }
        });
        
        console.log('=== LOGIN FORM HANDLER ATTACHED SUCCESSFULLY ===');
    },
    
    // Initialize register form
    initRegisterForm() {
        console.log('Initializing register form handlers');
        const registerForm = document.getElementById('registerForm');
        
        if (!registerForm) {
            console.log('Register form not found');
            return;
        }
        
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            console.log('Register form submitted');
            
            const submitBtn = document.getElementById('submitBtn');
            const originalText = submitBtn.textContent;
            const errorElement = document.getElementById('errorMessage');
            const successElement = document.getElementById('successMessage');
            
            // Clear previous messages
            if (errorElement) errorElement.style.display = 'none';
            if (successElement) successElement.style.display = 'none';
            
            // Show loading state
            submitBtn.disabled = true;
            submitBtn.textContent = 'Creating account...';
            
            // Get form data
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            
            // Validate passwords match
            if (password !== confirmPassword) {
                if (errorElement) {
                    errorElement.textContent = 'Passwords do not match';
                    errorElement.style.display = 'block';
                }
                submitBtn.disabled = false;
                submitBtn.textContent = originalText;
                return;
            }
            
            try {
                const response = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'include',
                    body: JSON.stringify({ name, email, password })
                });
                
                const result = await response.json();
                
                if (response.ok && result.success) {
                    if (successElement) {
                        successElement.textContent = 'Account created successfully! Redirecting to login...';
                        successElement.style.display = 'block';
                    }
                    
                    submitBtn.textContent = 'Success!';
                    
                    // Redirect to login after short delay
                    setTimeout(() => {
                        window.kyberLinkRouter.navigate('/login');
                    }, 2000);
                } else {
                    const errorMsg = result.error || 'Registration failed';
                    
                    if (errorElement) {
                        errorElement.textContent = errorMsg;
                        errorElement.style.display = 'block';
                    }
                    
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalText;
                }
            } catch (error) {
                console.error('Registration error:', error);
                
                if (errorElement) {
                    errorElement.textContent = 'Connection error. Please try again.';
                    errorElement.style.display = 'block';
                }
                
                submitBtn.disabled = false;
                submitBtn.textContent = originalText;
            }
        });
        
        console.log('Register form handler attached');
    },
    
    // Check authentication and redirect if needed
    async checkAuthAndRedirect() {
        try {
            const response = await fetch('/api/auth/status', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const result = await response.json();
                if (result.authenticated) {
                    console.log('User already has session cookie, auto-redirecting to dashboard');
                    // If user already has a session cookie, auto-redirect to dashboard
                    window.location.href = '/dashboard';
                }
            }
        } catch (error) {
            console.log('Auth check failed:', error);
        }
    },
    
    // Logout function
    async logout() {
        try {
            const response = await fetch('/api/auth/logout', {
                method: 'POST',
                credentials: 'include'
            });
            
            if (response.ok) {
                // Use window.location.href for logout to clear session completely
                window.location.href = '/login';
            }
        } catch (error) {
            console.error('Logout error:', error);
            // Force redirect on error too
            window.location.href = '/login';
        }
    }
};

// Export for use in other modules
window.KyberShieldAuth = KyberShieldAuth;