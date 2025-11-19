// Debug utility for conditional logging
class Debug {
    constructor() {
        this.enabled = window.location.hostname === 'localhost' || 
                      window.location.hostname === '127.0.0.1' ||
                      window.location.hostname.includes('local') ||
                      window.location.hostname.includes('192.168') ||
                      new URLSearchParams(window.location.search).has('debug') ||
                      true; // Enable debug logging for all environments during development
    }

    log(...args) {
        if (this.enabled) {
            console.log('[DEBUG]', ...args);
        }
    }

    error(...args) {
        // Always show errors, but prefix them
        console.error('[ERROR]', ...args);
    }

    warn(...args) {
        // Always show warnings, but prefix them
        console.warn('[WARN]', ...args);
    }

    info(...args) {
        if (this.enabled) {
            console.info('[INFO]', ...args);
        }
    }

    table(...args) {
        if (this.enabled) {
            console.table(...args);
        }
    }

    group(...args) {
        if (this.enabled) {
            console.group(...args);
        }
    }

    groupEnd() {
        if (this.enabled) {
            console.groupEnd();
        }
    }

    time(label) {
        if (this.enabled) {
            console.time(label);
        }
    }

    timeEnd(label) {
        if (this.enabled) {
            console.timeEnd(label);
        }
    }
}

// Global debug instance
const debug = new Debug();
