// Main JavaScript file for Expense Tracker

// Utility functions
const Utils = {
    // Show loading state
    showLoading: (element) => {
        element.classList.add('loading');
        element.disabled = true;
    },
    
    // Hide loading state
    hideLoading: (element) => {
        element.classList.remove('loading');
        element.disabled = false;
    },
    
    // Show notification
    showNotification: (message, type = 'info') => {
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        alert.style.cssText = 'top: 20px; right: 20px; z-index: 1050; min-width: 300px;';
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        document.body.appendChild(alert);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (alert.parentNode) {
                alert.parentNode.removeChild(alert);
            }
        }, 5000);
    },
    
    // Format currency
    formatCurrency: (amount) => {
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: 'USD'
        }).format(amount);
    }
};

// API client
const ApiClient = {
    // Make API request
    request: async (url, options = {}) => {
        const csrfToken = (() => {
            const meta = document.querySelector('meta[name="csrf-token"]');
            if (meta) {
                return meta.getAttribute('content');
            }
            const match = document.cookie.match(/csrf_token=([^;]+)/);
            return match ? decodeURIComponent(match[1]) : '';
        })();

        const config = {
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
                ...options.headers
            },
            cache: 'no-store',
            ...options
        };
        
        if (config.body && typeof config.body === 'object') {
            config.body = JSON.stringify(config.body);
        }
        
        try {
            const response = await fetch(url, config);
            
            // Check if response has content
            const contentType = response.headers.get('content-type');
            let data = null;
            
            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
            } else {
                // For non-JSON responses (like empty DELETE responses), try to parse as text
                const text = await response.text();
                if (text) {
                    try {
                        data = JSON.parse(text);
                    } catch (parseError) {
                        // If it's not JSON, return the text or empty object
                        data = text || {};
                    }
                } else {
                    // Empty response - return success object
                    data = { message: 'Success' };
                }
            }
            
            if (!response.ok) {
                // Create a custom error with status code and message
                const error = new Error(data.error || 'Request failed');
                error.status = response.status;
                error.response = data;
                throw error;
            }
            
            return data;
        } catch (error) {
            debug.error('API request failed:', error);
            throw error;
        }
    },
    
    // Dashboard API methods
    dashboard: {
        create: (data) => ApiClient.request('/api/dashboard/create', {
            method: 'POST',
            body: data
        }),
        
        get: (id) => ApiClient.request(`/api/dashboard/${id}`),
        
        update: (id, data) => ApiClient.request(`/api/dashboard/${id}`, {
            method: 'PUT',
            body: data
        }),
        
        delete: (id) => ApiClient.request(`/api/dashboard/${id}`, {
            method: 'DELETE'
        })
    },
    
    // Settings API methods
    settings: {
        updateApiKey: (apiKey) => ApiClient.request('/api/settings/update-api-key', {
            method: 'POST',
            body: { mistral_api_key: apiKey }
        })
    },
    
    // Expenses API methods
    expenses: {
        create: (dashboardId, data) => ApiClient.request(`/api/dashboard/${dashboardId}/expenses`, {
            method: 'POST',
            body: data
        }),
        
        get: (dashboardId) => {
            const ts = Date.now();
            return ApiClient.request(`/api/dashboard/${dashboardId}/expenses?_=${ts}`);
        },
        
        update: (dashboardId, expenseId, data) => ApiClient.request(`/api/dashboard/${dashboardId}/expenses/${expenseId}`, {
            method: 'PUT',
            body: data
        }),
        
        delete: (dashboardId, expenseId) => ApiClient.request(`/api/dashboard/${dashboardId}/expenses/${expenseId}`, {
            method: 'DELETE'
        })
    },
    
    // AI Processing API methods
    ai: {
        processCsv: (dashboardId, sessionId, prompt, csvData) => ApiClient.request(`/api/dashboard/${dashboardId}/ai/process`, {
            method: 'POST',
            body: { session_id: sessionId, prompt, csv_data: csvData }
        }),
        
        createSession: (dashboardId, csvData) => ApiClient.request(`/api/dashboard/${dashboardId}/ai/session`, {
            method: 'POST',
            body: { csv_data: csvData }
        }),
        
        getSession: (dashboardId, sessionId) => ApiClient.request(`/api/dashboard/${dashboardId}/ai/session/${sessionId}`),
        
        cleanup: (dashboardId, data) => ApiClient.request(`/api/dashboard/${dashboardId}/ai/cleanup`, {
            method: 'POST',
            body: data
        }),
        
        extractFromPdf: (dashboardId, base64Pdf, filename) => ApiClient.request(`/api/dashboard/${dashboardId}/ai/extract-pdf`, {
            method: 'POST',
            body: { pdf_data: base64Pdf, filename }
        })
    }
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            if (alert.parentNode) {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }
        }, 5000);
    });
    
    // Add smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Handle file upload drag and drop
    const fileUploadAreas = document.querySelectorAll('.border-dashed');
    fileUploadAreas.forEach(area => {
        area.addEventListener('dragover', function(e) {
            e.preventDefault();
            this.style.borderColor = '#0d6efd';
            this.style.backgroundColor = 'rgba(13, 110, 253, 0.05)';
        });
        
        area.addEventListener('dragleave', function(e) {
            e.preventDefault();
            this.style.borderColor = '#dee2e6';
            this.style.backgroundColor = '';
        });
        
        area.addEventListener('drop', function(e) {
            e.preventDefault();
            this.style.borderColor = '#dee2e6';
            this.style.backgroundColor = '';
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                const fileInput = this.querySelector('input[type="file"]');
                if (fileInput) {
                    // Create a new FileList (can't directly assign to fileInput.files)
                    const dataTransfer = new DataTransfer();
                    dataTransfer.items.add(files[0]);
                    fileInput.files = dataTransfer.files;
                    
                    // Trigger change event
                    fileInput.dispatchEvent(new Event('change', { bubbles: true }));
                }
            }
        });
    });
    
    debug.log('Expense Tracker initialized');
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { Utils, ApiClient };
}
