/**
 * VulnSleuth Web Interface - Main JavaScript
 * Interactive features and utilities
 */

// ==================== Theme Management ====================

/**
 * Initialize theme from saved setting
 */
function initializeTheme() {
    const savedTheme = localStorage.getItem('vulnsleuth-theme') || 'light';
    // If saved theme was system, cyber, or glassy, default to light
    const validTheme = ['light', 'dark'].includes(savedTheme) ? savedTheme : 'light';
    applyTheme(validTheme);
}

/**
 * Apply theme to document
 */
function applyTheme(theme) {
    // Only allow light or dark themes
    const validTheme = ['light', 'dark'].includes(theme) ? theme : 'light';
    document.body.setAttribute('data-theme', validTheme);
    localStorage.setItem('vulnsleuth-theme', validTheme);
}

/**
 * Toggle theme (for quick switching)
 */
function toggleTheme() {
    const currentTheme = document.body.getAttribute('data-theme');
    const nextTheme = currentTheme === 'light' ? 'dark' : 'light';
    
    applyTheme(nextTheme);
    
    // Update server if logged in
    if (isAuthenticated()) {
        updateThemeOnServer(nextTheme);
    }
}

/**
 * Update theme preference on server
 */
async function updateThemeOnServer(theme) {
    try {
        await fetch('/api/settings/theme', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ theme })
        });
    } catch (error) {
        console.error('Failed to update theme on server:', error);
    }
}

/**
 * Check if user is authenticated
 */
function isAuthenticated() {
    return document.body.classList.contains('authenticated');
}

// ==================== Notifications ====================

/**
 * Show notification message
 */
function showNotification(message, type = 'info', duration = 5000) {
    // Remove existing notifications
    const existing = document.querySelectorAll('.notification-toast');
    existing.forEach(n => n.remove());
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification-toast notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas fa-${getNotificationIcon(type)}"></i>
            <span>${message}</span>
        </div>
        <button class="notification-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // Add to document
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => notification.classList.add('show'), 10);
    
    // Auto remove
    if (duration > 0) {
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 300);
        }, duration);
    }
}

/**
 * Get icon for notification type
 */
function getNotificationIcon(type) {
    const icons = {
        success: 'check-circle',
        error: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    return icons[type] || 'info-circle';
}

// Add notification styles dynamically
const notificationStyles = document.createElement('style');
notificationStyles.textContent = `
    .notification-toast {
        position: fixed;
        top: 80px;
        right: -400px;
        max-width: 400px;
        background: var(--bg-secondary);
        border-radius: var(--radius-md);
        box-shadow: var(--shadow-lg);
        padding: var(--spacing-md);
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--spacing-md);
        z-index: 9999;
        transition: right 0.3s ease;
        border-left: 4px solid var(--accent-primary);
    }
    
    [data-theme="glassy"] .notification-toast {
        background: rgba(255, 255, 255, 0.15);
        backdrop-filter: blur(20px);
        border: 1px solid var(--border-color);
    }
    
    .notification-toast.show {
        right: 20px;
    }
    
    .notification-content {
        display: flex;
        align-items: center;
        gap: var(--spacing-md);
    }
    
    .notification-success {
        border-left-color: var(--success);
    }
    
    .notification-error {
        border-left-color: var(--danger);
    }
    
    .notification-warning {
        border-left-color: var(--warning);
    }
    
    .notification-info {
        border-left-color: var(--info);
    }
    
    .notification-close {
        background: transparent;
        border: none;
        color: var(--text-secondary);
        cursor: pointer;
        padding: var(--spacing-xs);
    }
    
    .notification-close:hover {
        color: var(--text-primary);
    }
`;
document.head.appendChild(notificationStyles);

// ==================== User Menu ====================

/**
 * Toggle user dropdown menu
 */
function toggleUserMenu() {
    const dropdown = document.getElementById('userDropdown');
    if (dropdown) {
        dropdown.classList.toggle('show');
        
        // Close when clicking outside
        if (dropdown.classList.contains('show')) {
            document.addEventListener('click', function closeUserMenu(e) {
                if (!dropdown.contains(e.target) && !e.target.closest('.user-btn')) {
                    dropdown.classList.remove('show');
                    document.removeEventListener('click', closeUserMenu);
                }
            });
        }
    }
}

// ==================== Global Search ====================

/**
 * Initialize global search
 */
function initializeGlobalSearch() {
    const searchInput = document.getElementById('globalSearch');
    if (searchInput) {
        let searchTimeout;
        searchInput.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                performGlobalSearch(e.target.value);
            }, 500);
        });
    }
}

/**
 * Perform global search
 */
async function performGlobalSearch(query) {
    if (!query || query.length < 2) return;
    
    try {
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
        const results = await response.json();
        displaySearchResults(results);
    } catch (error) {
        console.error('Search failed:', error);
    }
}

/**
 * Display search results
 */
function displaySearchResults(results) {
    // Implement search results display
    console.log('Search results:', results);
}

// ==================== Utility Functions ====================

/**
 * Format date to readable string
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;
    
    // Less than 1 minute
    if (diff < 60000) {
        return 'Just now';
    }
    
    // Less than 1 hour
    if (diff < 3600000) {
        const minutes = Math.floor(diff / 60000);
        return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    }
    
    // Less than 24 hours
    if (diff < 86400000) {
        const hours = Math.floor(diff / 3600000);
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    }
    
    // Less than 7 days
    if (diff < 604800000) {
        const days = Math.floor(diff / 86400000);
        return `${days} day${days > 1 ? 's' : ''} ago`;
    }
    
    // Default format
    return date.toLocaleDateString();
}

/**
 * Format file size to readable string
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Debounce function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showNotification('Copied to clipboard', 'success', 2000);
    } catch (error) {
        showNotification('Failed to copy to clipboard', 'error');
    }
}

/**
 * Validate email format
 */
function isValidEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

/**
 * Validate URL format
 */
function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

/**
 * Validate IP address
 */
function isValidIP(ip) {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6 = /^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$/;
    return ipv4.test(ip) || ipv6.test(ip);
}

// ==================== Modal Management ====================

/**
 * Show modal
 */
function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'flex';
        document.body.style.overflow = 'hidden';
    }
}

/**
 * Hide modal
 */
function hideModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
    }
}

/**
 * Close modal when clicking outside
 */
function setupModalCloseOnOutsideClick() {
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.style.display = 'none';
                document.body.style.overflow = 'auto';
            }
        });
    });
}

// ==================== Local Storage Management ====================

/**
 * Save to local storage
 */
function saveToLocalStorage(key, value) {
    try {
        localStorage.setItem(`vulnsleuth-${key}`, JSON.stringify(value));
        return true;
    } catch (error) {
        console.error('Failed to save to local storage:', error);
        return false;
    }
}

/**
 * Get from local storage
 */
function getFromLocalStorage(key, defaultValue = null) {
    try {
        const item = localStorage.getItem(`vulnsleuth-${key}`);
        return item ? JSON.parse(item) : defaultValue;
    } catch (error) {
        console.error('Failed to get from local storage:', error);
        return defaultValue;
    }
}

/**
 * Remove from local storage
 */
function removeFromLocalStorage(key) {
    try {
        localStorage.removeItem(`vulnsleuth-${key}`);
        return true;
    } catch (error) {
        console.error('Failed to remove from local storage:', error);
        return false;
    }
}

// ==================== Keyboard Shortcuts ====================

/**
 * Initialize keyboard shortcuts
 */
function initializeKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Ctrl/Cmd + K: Focus search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.getElementById('globalSearch');
            if (searchInput) searchInput.focus();
        }
        
        // Escape: Close modals
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal').forEach(modal => {
                modal.style.display = 'none';
            });
            document.body.style.overflow = 'auto';
        }
    });
}

// ==================== Auto-refresh ====================

let autoRefreshInterval = null;

/**
 * Start auto-refresh
 */
function startAutoRefresh(callback, interval = 30000) {
    stopAutoRefresh();
    autoRefreshInterval = setInterval(callback, interval);
}

/**
 * Stop auto-refresh
 */
function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

// ==================== Notifications Management ====================

let notificationCount = 0;

/**
 * Show notifications panel
 */
function showNotifications() {
    showNotification('No new notifications', 'info');
}

/**
 * Update notification badge
 */
function updateNotificationBadge(count) {
    const badge = document.querySelector('.notification-badge');
    if (badge) {
        notificationCount = count;
        badge.textContent = count;
        badge.style.display = count > 0 ? 'block' : 'none';
    }
}

// ==================== Scroll Utilities ====================

/**
 * Smooth scroll to element
 */
function scrollToElement(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

/**
 * Scroll to top
 */
function scrollToTop() {
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Add scroll-to-top button
const scrollTopBtn = document.createElement('button');
scrollTopBtn.className = 'scroll-top-btn';
scrollTopBtn.innerHTML = '<i class="fas fa-arrow-up"></i>';
scrollTopBtn.onclick = scrollToTop;
document.body.appendChild(scrollTopBtn);

// Show/hide scroll-to-top button
window.addEventListener('scroll', () => {
    if (window.scrollY > 300) {
        scrollTopBtn.classList.add('show');
    } else {
        scrollTopBtn.classList.remove('show');
    }
});

// Add scroll-to-top button styles
const scrollTopStyles = document.createElement('style');
scrollTopStyles.textContent = `
    .scroll-top-btn {
        position: fixed;
        bottom: 30px;
        right: 30px;
        width: 50px;
        height: 50px;
        border-radius: 50%;
        background: var(--accent-primary);
        color: white;
        border: none;
        font-size: 1.2rem;
        cursor: pointer;
        box-shadow: var(--shadow-lg);
        opacity: 0;
        visibility: hidden;
        transition: all var(--transition-fast);
        z-index: 1000;
    }
    
    .scroll-top-btn.show {
        opacity: 1;
        visibility: visible;
    }
    
    .scroll-top-btn:hover {
        transform: translateY(-5px);
        background: var(--accent-secondary);
    }
`;
document.head.appendChild(scrollTopStyles);

// ==================== Loading Indicator ====================

/**
 * Show loading indicator
 */
function showLoading(message = 'Loading...') {
    const loading = document.createElement('div');
    loading.id = 'global-loading';
    loading.className = 'loading-overlay';
    loading.innerHTML = `
        <div class="loading-spinner">
            <i class="fas fa-spinner fa-spin"></i>
            <p>${message}</p>
        </div>
    `;
    document.body.appendChild(loading);
}

/**
 * Hide loading indicator
 */
function hideLoading() {
    const loading = document.getElementById('global-loading');
    if (loading) {
        loading.remove();
    }
}

// Add loading styles
const loadingStyles = document.createElement('style');
loadingStyles.textContent = `
    .loading-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 9999;
    }
    
    .loading-spinner {
        text-align: center;
        color: white;
    }
    
    .loading-spinner i {
        font-size: 3rem;
        margin-bottom: 1rem;
    }
`;
document.head.appendChild(loadingStyles);

// ==================== Confirmation Dialogs ====================

/**
 * Show confirmation dialog
 */
function confirmAction(message, onConfirm, onCancel = null) {
    const confirmed = confirm(message);
    if (confirmed && onConfirm) {
        onConfirm();
    } else if (!confirmed && onCancel) {
        onCancel();
    }
}

// ==================== System Detection ====================

/**
 * Detect operating system
 */
function detectOS() {
    const userAgent = window.navigator.userAgent;
    const platform = window.navigator.platform;
    const macosPlatforms = ['Macintosh', 'MacIntel', 'MacPPC', 'Mac68K'];
    const windowsPlatforms = ['Win32', 'Win64', 'Windows', 'WinCE'];
    const iosPlatforms = ['iPhone', 'iPad', 'iPod'];
    
    if (macosPlatforms.indexOf(platform) !== -1) {
        return 'MacOS';
    } else if (iosPlatforms.indexOf(platform) !== -1) {
        return 'iOS';
    } else if (windowsPlatforms.indexOf(platform) !== -1) {
        return 'Windows';
    } else if (/Android/.test(userAgent)) {
        return 'Android';
    } else if (/Linux/.test(platform)) {
        return 'Linux';
    }
    
    return 'Unknown';
}

/**
 * Detect browser
 */
function detectBrowser() {
    const userAgent = navigator.userAgent;
    
    if (userAgent.indexOf('Firefox') > -1) {
        return 'Firefox';
    } else if (userAgent.indexOf('Chrome') > -1) {
        return 'Chrome';
    } else if (userAgent.indexOf('Safari') > -1) {
        return 'Safari';
    } else if (userAgent.indexOf('Edge') > -1) {
        return 'Edge';
    } else if (userAgent.indexOf('Opera') > -1 || userAgent.indexOf('OPR') > -1) {
        return 'Opera';
    }
    
    return 'Unknown';
}

// ==================== Initialization ====================

/**
 * Initialize all features when DOM is ready
 */
document.addEventListener('DOMContentLoaded', () => {
    // Initialize theme
    initializeTheme();
    
    // Initialize global search
    initializeGlobalSearch();
    
    // Initialize keyboard shortcuts
    initializeKeyboardShortcuts();
    
    // Setup modal close on outside click
    setupModalCloseOnOutsideClick();
    
    // Listen for system theme changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        const theme = localStorage.getItem('vulnsleuth-theme');
        if (theme === 'system') {
            document.body.setAttribute('data-theme', e.matches ? 'dark' : 'light');
        }
    });
    
    // Add smooth scrolling to all anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
    
    console.log('VulnSleuth Web Interface initialized');
    console.log(`OS: ${detectOS()}, Browser: ${detectBrowser()}`);
});

// ==================== Export Functions ====================

// Make functions available globally
window.VulnSleuth = {
    // Theme
    applyTheme,
    toggleTheme,
    
    // Notifications
    showNotification,
    showNotifications,
    updateNotificationBadge,
    
    // Modals
    showModal,
    hideModal,
    
    // Loading
    showLoading,
    hideLoading,
    
    // Utilities
    formatDate,
    formatFileSize,
    copyToClipboard,
    isValidEmail,
    isValidUrl,
    isValidIP,
    scrollToElement,
    scrollToTop,
    
    // Auto-refresh
    startAutoRefresh,
    stopAutoRefresh,
    
    // User menu
    toggleUserMenu,
    
    // System detection
    detectOS,
    detectBrowser
};
