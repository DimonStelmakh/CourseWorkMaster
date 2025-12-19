class ApiClient {
    constructor() {
        this.baseUrl = '/api';
        this.token = localStorage.getItem('access_token');
    }
    
    setToken(token) {
        this.token = token;
        if (token) {
            localStorage.setItem('access_token', token);
        } else {
            localStorage.removeItem('access_token');
        }
    }
    
    getToken() {
        return this.token || localStorage.getItem('access_token');
    }
    
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        if (this.getToken()) {
            headers['Authorization'] = `Bearer ${this.getToken()}`;
        }
        
        try {
            const response = await fetch(url, {
                ...options,
                headers
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.detail || 'Request failed');
            }
            
            return data;
        } catch (error) {
            if (error.message === 'Invalid or expired token') {
                this.setToken(null);
                window.location.reload();
            }
            throw error;
        }
    }
    
    // Auth endpoints
    async register(username, email, password) {
        return this.request('/auth/register', {
            method: 'POST',
            body: JSON.stringify({ username, email, password })
        });
    }
    
    async login(username, password, biometricData = null) {
        const body = { username, password };
        // Only add biometric_data if it's not null and not empty
        if (biometricData && Object.keys(biometricData).length > 0) {
            body.biometric_data = biometricData;
        }
        return this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify(body)
        });
    }
    
    async verifyMfa(mfaToken, code) {
        return this.request('/auth/verify-mfa', {
            method: 'POST',
            body: JSON.stringify({ mfa_token: mfaToken, code })
        });
    }
    
    async logout() {
        try {
            await this.request('/auth/logout', { method: 'POST' });
        } finally {
            this.setToken(null);
        }
    }
    
    async getCurrentUser() {
        return this.request('/auth/me');
    }
    
    async setupTotp() {
        return this.request('/auth/setup-totp', { method: 'POST' });
    }
    
    async confirmTotp(code, backupCodes) {
        return this.request('/auth/confirm-totp', {
            method: 'POST',
            body: JSON.stringify({ code, backup_codes: backupCodes })
        });
    }
    
    async disableTotp(code) {
        return this.request('/auth/disable-totp', {
            method: 'POST',
            body: JSON.stringify({ code, backup_codes: [] })
        });
    }
    
    async requestPasswordReset(email) {
        return this.request('/auth/request-password-reset', {
            method: 'POST',
            body: JSON.stringify({ email })
        });
    }
    
    async resetPassword(token, newPassword) {
        return this.request('/auth/reset-password', {
            method: 'POST',
            body: JSON.stringify({ token, new_password: newPassword })
        });
    }
    
    async verifyEmail(token) {
        return this.request(`/auth/verify-email/${token}`);
    }
    
    // Biometric endpoints
    async collectBiometricData(dataType, data, deviceCategory = null) {
        return this.request('/biometric/collect', {
            method: 'POST',
            body: JSON.stringify({ 
                data_type: dataType, 
                data,
                device_category: deviceCategory
            })
        });
    }
    
    async analyzeBehavior(dataType = null) {
        const params = dataType ? `?data_type=${dataType}` : '';
        return this.request(`/biometric/analyze${params}`, { method: 'POST' });
    }
    
    async updateProfile(dataType) {
        return this.request(`/biometric/update-profile?data_type=${dataType}`, {
            method: 'POST'
        });
    }
    
    async getProfileStatus() {
        return this.request('/biometric/profile-status');
    }
    
    async getTrustScore() {
        return this.request('/biometric/trust-score');
    }
    
    // Dashboard endpoints
    async getUserDashboard() {
        return this.request('/dashboard/user');
    }
    
    async getAdminDashboard() {
        return this.request('/dashboard/admin');
    }
    
    async getSecurityEvents(page = 1, pageSize = 20) {
        return this.request(`/dashboard/events?page=${page}&page_size=${pageSize}`);
    }
}

// Global instance
window.api = new ApiClient();
