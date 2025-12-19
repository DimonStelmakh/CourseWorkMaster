class App {
    constructor() {
        this.currentUser = null;
        this.mfaToken = null;
        this.backupCodes = [];
        this.trustChart = null;
        
        this.init();
    }
    
    async init() {
        this.bindEvents();
        
        // Check URL for special routes
        const path = window.location.pathname;
        const params = new URLSearchParams(window.location.search);
        
        // Handle email verification /verify-email/{token}
        if (path.startsWith('/verify-email/')) {
            const token = path.replace('/verify-email/', '');
            if (token) {
                this.handleEmailVerification(token);
                return;
            }
        }
        
        // Handle password reset from email link
        if (path === '/reset-password' || params.has('token')) {
            const token = params.get('token');
            if (token) {
                this.resetToken = token;
                this.showView('reset-password');
                return;
            }
        }
        
        // Check if already logged in
        if (api.getToken()) {
            try {
                await this.loadDashboard();
            } catch (error) {
                api.setToken(null);
                this.showView('login');
            }
        } else {
            this.showView('login');
        }
    }
    
    bindEvents() {
        // Login form
        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });
        
        // Register form
        document.getElementById('register-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleRegister();
        });
        
        // MFA form
        document.getElementById('mfa-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleMfa();
        });
        
        // Forgot password form
        document.getElementById('forgot-password-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleForgotPassword();
        });
        
        // Reset password form
        document.getElementById('reset-password-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleResetPassword();
        });
        
        // View toggles
        document.getElementById('show-register').addEventListener('click', (e) => {
            e.preventDefault();
            this.showView('register');
        });
        
        document.getElementById('show-login').addEventListener('click', (e) => {
            e.preventDefault();
            this.showView('login');
        });
        
        document.getElementById('show-reset').addEventListener('click', (e) => {
            e.preventDefault();
            this.showView('forgot-password');
        });
        
        document.getElementById('show-login-from-forgot').addEventListener('click', (e) => {
            e.preventDefault();
            this.showView('login');
        });
        
        // TOTP setup
        document.getElementById('setup-totp-btn').addEventListener('click', () => {
            this.setupTotp();
        });
        
        document.getElementById('totp-confirm-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.confirmTotp();
        });
        
        // Start collecting keystroke data on password field
        const passwordField = document.getElementById('password');
        passwordField.addEventListener('focus', () => {
            window.biometricCollector.start();
        });
    }
    
    showView(view) {
        const views = ['login', 'register', 'mfa', 'dashboard', 'forgot-password', 'reset-password', 'verify-email'];
        views.forEach(v => {
            const el = document.getElementById(`${v}-view`);
            if (el) {
                el.classList.toggle('d-none', v !== view);
            }
        });
        
        this.updateNavigation(view === 'dashboard');
    }
    
    updateNavigation(isLoggedIn) {
        const navItems = document.getElementById('nav-items');
        
        if (isLoggedIn && this.currentUser) {
            navItems.innerHTML = `
                <span class="navbar-text text-white me-3">
                    <i class="bi bi-person-circle"></i> ${this.currentUser.username}
                </span>
                <button class="btn btn-outline-light btn-sm" id="logout-btn">
                    <i class="bi bi-box-arrow-right"></i> Вийти
                </button>
            `;
            
            document.getElementById('logout-btn').addEventListener('click', () => {
                this.handleLogout();
            });
        } else {
            navItems.innerHTML = '';
        }
    }
    
    showError(elementId, message) {
        const el = document.getElementById(elementId);
        // Handle object errors
        if (typeof message === 'object') {
            message = message.detail || JSON.stringify(message);
        }
        el.textContent = message;
        el.classList.remove('d-none');
        
        setTimeout(() => {
            el.classList.add('d-none');
        }, 5000);
    }
    
    async handleLogin() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        try {
            // Get keystroke biometric data collected during password typing
            const keystrokeData = window.biometricCollector.getLoginKeystrokeData();
            
            // Also collect any mouse data from the login form interaction
            const mouseData = window.biometricCollector.getMouseData();
            
            // Get touch data (for mobile)
            const touchData = window.biometricCollector.getTouchData();
            
            // Get device category
            const deviceCategory = window.biometricCollector.getDeviceCategory();
            
            // Prepare biometric data for login
            const biometricData = {
                device_category: deviceCategory
            };
            
            if (keystrokeData && keystrokeData.length > 0) {
                biometricData.keystroke = keystrokeData;
            }
            if (mouseData && mouseData.length > 0) {
                biometricData.mouse = mouseData;
            }
            if (touchData && touchData.length > 0) {
                biometricData.touch = touchData;
            }
            
            // Send login with biometric data
            const response = await api.login(
                username, 
                password, 
                Object.keys(biometricData).length > 1 ? biometricData : null  // > 1 because device_category is always there
            );
            
            if (response.requires_mfa) {
                this.mfaToken = response.mfa_token;
                
                // Show MFA reason
                this.showMfaReason(response.mfa_reason, response.trust_score);
                
                this.showView('mfa');
            } else {
                api.setToken(response.access_token);
                this.currentUser = response.user;
                await this.loadDashboard();
            }
        } catch (error) {
            this.showError('login-error', error.message || error);
        }
    }
    
    showMfaReason(reason, trustScore) {
        const reasonBlock = document.getElementById('mfa-reason-block');
        const reasonText = document.getElementById('mfa-reason-text');
        const trustScoreBlock = document.getElementById('mfa-trust-score');
        const trustValue = document.getElementById('mfa-trust-value');
        
        if (!reasonBlock || !reason) {
            if (reasonBlock) reasonBlock.classList.add('d-none');
            return;
        }
        
        // Translate reason to Ukrainian
        const reasonTranslations = {
            'no_biometric_profile': 'Поведінковий профіль ще не сформовано. Потрібно більше зразків.',
            'no_biometric_data': 'Не отримано біометричні дані при вході.',
            'no_matching_biometric_type': 'Відсутній профіль для цього типу пристрою.',
            'no_profile_for_device': 'Профіль для цього типу пристрою ще не сформовано. Ви маєте профіль для іншого пристрою.',
            'biometric_anomaly': 'Виявлено аномалію поведінки! Ваша поведінка відрізняється від звичної.',
            'verification_required': 'Потрібна додаткова верифікація.'
        };
        
        reasonText.textContent = reasonTranslations[reason] || reason;
        reasonBlock.classList.remove('d-none');
        
        // Change alert style based on reason
        reasonBlock.classList.remove('alert-info', 'alert-warning', 'alert-danger');
        if (reason === 'biometric_anomaly') {
            reasonBlock.classList.add('alert-danger');
        } else if (reason === 'no_biometric_profile' || reason === 'no_profile_for_device') {
            reasonBlock.classList.add('alert-info');
        } else {
            reasonBlock.classList.add('alert-warning');
        }
        
        // Show trust score if available
        if (trustScore !== undefined && trustScore !== null) {
            trustValue.textContent = `${(trustScore * 100).toFixed(1)}%`;
            trustScoreBlock.classList.remove('d-none');
        } else {
            trustScoreBlock.classList.add('d-none');
        }
    }
    
    async handleRegister() {
        const username = document.getElementById('reg-username').value;
        const email = document.getElementById('reg-email').value;
        const password = document.getElementById('reg-password').value;
        const password2 = document.getElementById('reg-password2').value;
        
        if (password !== password2) {
            this.showError('register-error', 'Паролі не співпадають');
            return;
        }
        
        try {
            await api.register(username, email, password);
            alert('Реєстрація успішна! Перевірте email для підтвердження акаунту.');
            this.showView('login');
        } catch (error) {
            this.showError('register-error', error.message || error);
        }
    }
    
    async handleForgotPassword() {
        const email = document.getElementById('reset-email').value;
        const successEl = document.getElementById('forgot-success');
        const errorEl = document.getElementById('forgot-error');
        
        // Hide previous messages
        successEl.classList.add('d-none');
        errorEl.classList.add('d-none');
        
        try {
            await api.requestPasswordReset(email);
            successEl.textContent = 'Якщо акаунт з такою адресою існує, ми надіслали посилання для скидання пароля.';
            successEl.classList.remove('d-none');
            document.getElementById('reset-email').value = '';
        } catch (error) {
            // Even on error, show success message for security (don't reveal if email exists)
            successEl.textContent = 'Якщо акаунт з такою адресою існує, ми надіслали посилання для скидання пароля.';
            successEl.classList.remove('d-none');
        }
    }
    
    async handleResetPassword() {
        const password = document.getElementById('new-password').value;
        const password2 = document.getElementById('new-password2').value;
        const successEl = document.getElementById('reset-success');
        const errorEl = document.getElementById('reset-error');
        
        // Hide previous messages
        successEl.classList.add('d-none');
        errorEl.classList.add('d-none');
        
        if (password !== password2) {
            this.showError('reset-error', 'Паролі не співпадають');
            return;
        }
        
        if (!this.resetToken) {
            this.showError('reset-error', 'Невалідне посилання для скидання пароля');
            return;
        }
        
        try {
            await api.resetPassword(this.resetToken, password);
            successEl.textContent = 'Пароль успішно змінено! Зараз ви будете перенаправлені на сторінку входу.';
            successEl.classList.remove('d-none');
            
            // Redirect to login after 3 seconds
            setTimeout(() => {
                window.location.href = '/';
            }, 3000);
        } catch (error) {
            this.showError('reset-error', error.message || 'Помилка скидання пароля. Можливо, посилання застаріло.');
        }
    }
    
    async handleEmailVerification(token) {
        this.showView('verify-email');
        
        const loadingEl = document.getElementById('verify-loading');
        const resultEl = document.getElementById('verify-result');
        const headerEl = document.getElementById('verify-header');
        const iconEl = document.getElementById('verify-icon');
        const messageEl = document.getElementById('verify-message');
        
        try {
            await api.verifyEmail(token);
            
            // Success
            loadingEl.classList.add('d-none');
            resultEl.classList.remove('d-none');
            headerEl.classList.add('bg-success');
            iconEl.classList.add('bi-check-circle-fill', 'text-success');
            messageEl.textContent = 'Email успішно підтверджено! Тепер ви можете увійти.';
            
        } catch (error) {
            // Error
            loadingEl.classList.add('d-none');
            resultEl.classList.remove('d-none');
            headerEl.classList.add('bg-danger');
            iconEl.classList.add('bi-x-circle-fill', 'text-danger');
            messageEl.textContent = 'Помилка підтвердження. Посилання недійсне або застаріло.';
        }
    }
    
    async handleMfa() {
        const code = document.getElementById('mfa-code').value;
        
        try {
            const response = await api.verifyMfa(this.mfaToken, code);
            api.setToken(response.access_token);
            this.currentUser = response.user;
            await this.loadDashboard();
        } catch (error) {
            this.showError('mfa-error', error.message);
        }
    }
    
    async handleLogout() {
        try {
            // Stop biometric collection
            window.biometricCollector.stop();
            
            // Stop dashboard refresh
            if (this.refreshInterval) {
                clearInterval(this.refreshInterval);
                this.refreshInterval = null;
            }
            
            await api.logout();
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            api.setToken(null);
            this.currentUser = null;
            this.showView('login');
        }
    }
    
    async loadDashboard() {
        try {
            const dashboard = await api.getUserDashboard();
            this.currentUser = dashboard.user;
            
            // Start biometric collection
            this.startBiometricCollection();
            
            // Update UI
            this.showView('dashboard');
            this.renderDashboard(dashboard);
            
            // Periodic refresh
            this.startDashboardRefresh();
        } catch (error) {
            console.error('Dashboard load error:', error);
            throw error;
        }
    }
    
    startBiometricCollection() {
        window.biometricCollector.onDataReady = async (batch) => {
            try {
                await api.collectBiometricData(batch.data_type, batch.data, batch.device_category);
            } catch (error) {
                console.error('Failed to send biometric data:', error);
            }
        };
        
        // Update live counter in UI
        window.biometricCollector.onCountUpdate = (counts) => {
            const keystrokeCounter = document.getElementById('keystroke-live-count');
            if (keystrokeCounter) {
                keystrokeCounter.textContent = counts.keystroke;
            }
        };
        
        window.biometricCollector.start();
    }
    
    startDashboardRefresh() {
        // Clear any existing interval
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
        
        this.refreshInterval = setInterval(async () => {
            try {
                const trustScore = await api.getTrustScore();
                this.updateTrustScore(trustScore);
            } catch (error) {
                // Silently ignore 403 errors (happens when logged out)
                if (error.message && !error.message.includes('403')) {
                    console.error('Trust score refresh error:', error);
                }
            }
        }, 10000); // Refresh every 10 seconds
    }
    
    renderDashboard(data) {
        // User info
        document.getElementById('user-role').textContent = data.user.role;
        
        // Check if user has trained profiles
        const profileStatus = data.profile_status || {};
        const deviceStatus = profileStatus.device_status || {};
        const hasDesktopProfile = deviceStatus.desktop?.trained || false;
        const hasMobileProfile = deviceStatus.mobile?.trained || false;
        const hasAnyProfile = hasDesktopProfile || hasMobileProfile;
        
        // Trust score - add note if no profile
        const trustData = {
            current_score: data.current_trust_score,
            threshold: data.trust_score_threshold,
            status: data.current_trust_score >= 0.85 ? 'normal' : 
                    data.current_trust_score >= 0.7 ? 'warning' : 'critical'
        };
        
        if (!hasAnyProfile) {
            trustData.note = 'no_profile';
        }
        
        this.updateTrustScore(trustData);
        
        // Profile status (now with detailed data)
        if (data.profile_status) {
            this.renderProfileStatus(data.profile_status);
        }
        
        // TOTP status
        const totpStatus = document.getElementById('totp-status');
        if (data.user.totp_enabled) {
            totpStatus.textContent = 'Увімкнено';
            totpStatus.className = 'badge bg-success';
            document.getElementById('setup-totp-btn').textContent = 'Вимкнути TOTP';
        } else {
            totpStatus.textContent = 'Вимкнено';
            totpStatus.className = 'badge bg-secondary';
            document.getElementById('setup-totp-btn').textContent = 'Налаштувати TOTP';
        }
        
        // Trust score history chart
        this.renderTrustChart(data.trust_score_history);
        
        // Recent events
        this.renderEvents(data.recent_events);
        
        // Active sessions
        this.renderSessions(data.active_sessions);
    }
    
    updateTrustScore(data) {
        const scoreEl = document.getElementById('trust-score-value');
        const statusEl = document.getElementById('trust-score-status');
        const card = document.getElementById('trust-score-card');
        
        const score = (data.current_score * 100).toFixed(1);
        scoreEl.textContent = `${score}%`;
        
        // Update status
        card.classList.remove('trust-high', 'trust-medium', 'trust-low');
        
        if (data.status === 'normal') {
            card.classList.add('trust-high');
            // Check if there's a note about missing profile
            if (data.note === 'no_profile') {
                statusEl.textContent = 'Профіль не сформовано';
                statusEl.className = 'text-muted';
            } else if (data.note === 'no_recent_data') {
                statusEl.textContent = 'Очікування даних';
                statusEl.className = 'text-muted';
            } else {
                statusEl.textContent = 'Нормальний';
                statusEl.className = 'text-success';
            }
        } else if (data.status === 'warning') {
            card.classList.add('trust-medium');
            statusEl.textContent = 'Увага';
            statusEl.className = 'text-warning';
        } else {
            card.classList.add('trust-low');
            statusEl.textContent = 'Критичний';
            statusEl.className = 'text-danger';
        }
    }
    
    renderProfileStatus(profileData) {
        const minRequired = profileData.min_required || 30;
        const deviceStatus = profileData.device_status || {};
        const samplesByDevice = profileData.sample_counts_by_device || {};
        
        // Desktop samples
        const desktopKeystroke = deviceStatus.desktop?.keystroke_samples || 0;
        const desktopMouse = deviceStatus.desktop?.mouse_samples || 0;
        
        // Mobile samples  
        const mobileKeystroke = deviceStatus.mobile?.keystroke_samples || 0;
        const mobileTouch = deviceStatus.mobile?.touch_samples || 0;
        const mobileSensor = deviceStatus.mobile?.sensor_samples || 0;
        
        // Update desktop progress bars
        this.updateProgressBar('keystroke', desktopKeystroke, minRequired, 'bg-primary');
        this.updateProgressBar('mouse', desktopMouse, minRequired, 'bg-primary');
        
        // Update mobile progress bars
        this.updateProgressBar('mobile-keystroke', mobileKeystroke, minRequired, 'bg-info');
        this.updateProgressBar('touch', mobileTouch, minRequired, 'bg-info');
        this.updateProgressBar('sensor', mobileSensor, minRequired, 'bg-info');
        
        // Desktop badge
        const desktopBadge = document.getElementById('desktop-ready-badge');
        if (desktopBadge) {
            const desktopTrained = deviceStatus.desktop?.trained;
            const desktopKeystrokeTrained = deviceStatus.desktop?.keystroke_trained;
            const desktopMouseTrained = deviceStatus.desktop?.mouse_trained;
            
            if (desktopTrained) {
                desktopBadge.className = 'badge bg-success';
                desktopBadge.textContent = '✓ Готово';
            } else if (desktopKeystrokeTrained || desktopMouseTrained) {
                desktopBadge.className = 'badge bg-warning text-dark';
                desktopBadge.textContent = 'Частково';
            } else if (desktopKeystroke > 0 || desktopMouse > 0) {
                desktopBadge.className = 'badge bg-warning text-dark';
                desktopBadge.textContent = 'Збір даних...';
            } else {
                desktopBadge.className = 'badge bg-secondary';
                desktopBadge.textContent = 'Немає даних';
            }
        }
        
        // Mobile badge
        const mobileBadge = document.getElementById('mobile-ready-badge');
        if (mobileBadge) {
            const mobileTrained = deviceStatus.mobile?.trained;
            const mobileKeystrokeTrained = deviceStatus.mobile?.keystroke_trained;
            const mobileTouchTrained = deviceStatus.mobile?.touch_trained;
            
            if (mobileTrained) {
                mobileBadge.className = 'badge bg-success';
                mobileBadge.textContent = '✓ Готово';
            } else if (mobileKeystrokeTrained || mobileTouchTrained) {
                mobileBadge.className = 'badge bg-warning text-dark';
                mobileBadge.textContent = 'Частково';
            } else if (mobileKeystroke > 0 || mobileTouch > 0 || mobileSensor > 0) {
                mobileBadge.className = 'badge bg-warning text-dark';
                mobileBadge.textContent = 'Збір даних...';
            } else {
                mobileBadge.className = 'badge bg-secondary';
                mobileBadge.textContent = 'Немає даних';
            }
        }
        
        // Status message
        const statusMessage = document.getElementById('profile-status-message');
        if (statusMessage) {
            const desktopReady = deviceStatus.desktop?.trained;
            const mobileReady = deviceStatus.mobile?.trained;
            
            if (desktopReady && mobileReady) {
                statusMessage.className = 'alert alert-success py-2 mb-0 small';
                statusMessage.innerHTML = '<i class="bi bi-check-circle"></i> Обидва профілі готові! MFA пропускатиметься при відповідності поведінці.';
            } else if (desktopReady) {
                statusMessage.className = 'alert alert-success py-2 mb-0 small';
                statusMessage.innerHTML = '<i class="bi bi-check-circle"></i> ПК профіль готовий! MFA пропускатиметься при вході з ПК.';
            } else if (mobileReady) {
                statusMessage.className = 'alert alert-success py-2 mb-0 small';
                statusMessage.innerHTML = '<i class="bi bi-check-circle"></i> Мобільний профіль готовий! MFA пропускатиметься при вході з телефону.';
            } else {
                statusMessage.className = 'alert alert-info py-2 mb-0 small';
                statusMessage.innerHTML = '<i class="bi bi-info-circle"></i> Продовжуйте користуватись системою для формування профілю. Потрібно 30+ зразків.';
            }
        }
    }
    
    updateProgressBar(id, count, minRequired, colorClass) {
        const progress = document.getElementById(`${id}-progress`);
        const countEl = document.getElementById(`${id}-count`);
        
        if (progress && countEl) {
            const percent = Math.min((count / minRequired) * 100, 100);
            progress.style.width = `${percent}%`;
            countEl.textContent = `${count}/${minRequired}`;
            
            // Change color when ready
            progress.classList.remove('bg-primary', 'bg-info', 'bg-success');
            if (count >= minRequired) {
                progress.classList.add('bg-success');
            } else {
                progress.classList.add(colorClass);
            }
        }
    }
    
    renderTrustChart(history) {
        const ctx = document.getElementById('trust-history-chart').getContext('2d');
        
        if (this.trustChart) {
            this.trustChart.destroy();
        }
        
        const labels = history.map(h => {
            const date = new Date(h.timestamp);
            return date.toLocaleTimeString('uk-UA', { hour: '2-digit', minute: '2-digit' });
        });
        
        const scores = history.map(h => h.score * 100);
        
        this.trustChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Trust Score (%)',
                    data: scores,
                    borderColor: '#0d6efd',
                    backgroundColor: 'rgba(13, 110, 253, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        min: 0,
                        max: 100,
                        ticks: {
                            callback: value => `${value}%`
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }
    
    renderEvents(events) {
        const tbody = document.querySelector('#events-table tbody');
        tbody.innerHTML = '';
        
        const eventLabels = {
            'LOGIN_SUCCESS': { text: 'Вхід', class: 'bg-success' },
            'LOGIN_FAILED': { text: 'Невдалий вхід', class: 'bg-danger' },
            'LOGOUT': { text: 'Вихід', class: 'bg-secondary' },
            'MFA_TRIGGERED': { text: 'MFA запит', class: 'bg-warning' },
            'MFA_SUCCESS': { text: 'MFA успіх', class: 'bg-success' },
            'ANOMALY_DETECTED': { text: 'Аномалія', class: 'bg-danger' }
        };
        
        events.forEach(event => {
            const label = eventLabels[event.event_type] || { text: event.event_type, class: 'bg-info' };
            const date = new Date(event.timestamp);
            
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><span class="badge ${label.class}">${label.text}</span></td>
                <td>${date.toLocaleString('uk-UA')}</td>
            `;
            tbody.appendChild(row);
        });
    }
    
    renderSessions(sessions) {
        const tbody = document.querySelector('#sessions-table tbody');
        tbody.innerHTML = '';
        
        sessions.forEach(session => {
            const date = new Date(session.last_activity);
            const trustClass = session.trust_score >= 0.85 ? 'text-success' :
                              session.trust_score >= 0.7 ? 'text-warning' : 'text-danger';
            
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${session.ip_address || 'N/A'}</td>
                <td class="${trustClass}">${(session.trust_score * 100).toFixed(0)}%</td>
                <td>${date.toLocaleString('uk-UA')}</td>
            `;
            tbody.appendChild(row);
        });
    }
    
    async setupTotp() {
        // Check if TOTP is already enabled (button text indicates state)
        const btn = document.getElementById('setup-totp-btn');
        const isEnabled = btn.textContent.includes('Вимкнути');
        
        if (isEnabled) {
            // Disable TOTP - ask for current code
            const code = prompt('Введіть поточний TOTP код для вимкнення:');
            if (!code) return;
            
            try {
                await api.disableTotp(code);
                alert('TOTP успішно вимкнено!');
                await this.loadDashboard();
            } catch (error) {
                alert('Помилка вимкнення TOTP: ' + error.message);
            }
        } else {
            // Enable TOTP - show setup modal
            try {
                const data = await api.setupTotp();
                
                document.getElementById('totp-qr').src = `data:image/png;base64,${data.qr_code}`;
                document.getElementById('totp-secret').textContent = data.secret;
                
                this.backupCodes = data.backup_codes;
                const codesEl = document.getElementById('backup-codes');
                codesEl.innerHTML = data.backup_codes.map(c => `<code>${c}</code>`).join(' ');
                
                const modal = new bootstrap.Modal(document.getElementById('totp-modal'));
                modal.show();
            } catch (error) {
                alert('Помилка налаштування TOTP: ' + error.message);
            }
        }
    }
    
    async confirmTotp() {
        const code = document.getElementById('totp-verify-code').value;
        
        try {
            await api.confirmTotp(code, this.backupCodes);
            
            bootstrap.Modal.getInstance(document.getElementById('totp-modal')).hide();
            alert('TOTP успішно налаштовано!');
            
            // Reload dashboard
            await this.loadDashboard();
        } catch (error) {
            alert('Помилка підтвердження: ' + error.message);
        }
    }
}

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    window.app = new App();
});
