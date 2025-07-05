import Debug from 'debug';

const debug = Debug('localtunnel:cert-auth');

class CertificateAuth {
    constructor(options = {}) {
        this.enabled = options.enabled || false;
        this.allowedClients = new Set(options.allowedClients || []);
        this.requireClientCert = options.requireClientCert !== false;
        this.logAll = options.logAll || false;
    }

    // Middleware for Koa
    middleware() {
        return async (ctx, next) => {
            if (!this.enabled) {
                await next();
                return;
            }

            const certInfo = this.extractCertificateInfo(ctx.request);
            
            if (this.logAll) {
                debug('Certificate info:', certInfo);
            }

            // Attach certificate info to context for later use
            ctx.state.clientCert = certInfo;

            // Allow requests with valid JWT to bypass cert validation
               const tokenFromHeader = ctx.headers.authorization?.startsWith('Bearer ')
                ? ctx.headers.authorization.split(' ')[1]
                : null;

                const tokenFromQuery = ctx.query?.token;

                const hasJWT = !!(tokenFromHeader || tokenFromQuery);


                if (!hasJWT && !this.validateCertificate(certInfo)) {
                    ctx.status = 401;
                    ctx.body = {
                        error: 'Client certificate authentication failed',
                        details: certInfo.error || 'Invalid or missing client certificate'
                    };
                    return;
                }

            debug('Client certificate validated:', certInfo.commonName);
            await next();
        };
    }

    // Extract certificate information from request headers (set by Nginx)
    extractCertificateInfo(request) {
        const headers = request.headers;
        
        return {
            verified: headers['x-ssl-client-verify'] === 'SUCCESS',
            subjectDN: headers['x-ssl-client-s-dn'],
            issuerDN: headers['x-ssl-client-i-dn'],
            serial: headers['x-ssl-client-serial'],
            fingerprint: headers['x-ssl-client-fingerprint'],
            cert: headers['x-ssl-client-cert'],
            commonName: this.extractCommonName(headers['x-ssl-client-s-dn']),
            error: headers['x-ssl-client-verify'] !== 'SUCCESS' ? 
                   `Verification failed: ${headers['x-ssl-client-verify']}` : null
        };
    }

    // Extract Common Name from Distinguished Name
    extractCommonName(dn) {
        if (!dn) return null;
        const cnMatch = dn.match(/CN=([^,]+)/);
        return cnMatch ? cnMatch[1] : null;
    }

    // Validate certificate
    validateCertificate(certInfo) {
        // Must be verified by Nginx
        if (!certInfo.verified) {
            debug('Certificate verification failed:', certInfo.error);
            return false;
        }

        // Check if client certificate is required
        if (this.requireClientCert && !certInfo.subjectDN) {
            debug('Client certificate required but not provided');
            return false;
        }

        // Check allowed clients list (if configured)
        if (this.allowedClients.size > 0 && certInfo.commonName) {
            if (!this.allowedClients.has(certInfo.commonName)) {
                debug('Client not in allowed list:', certInfo.commonName);
                return false;
            }
        }

        return true;
    }

    // Validate certificate for raw HTTP requests (not Koa)
    validateRawRequest(req) {
        if (!this.enabled) {
            return { valid: true, info: null };
        }

        const certInfo = {
            verified: req.headers['x-ssl-client-verify'] === 'SUCCESS',
            subjectDN: req.headers['x-ssl-client-s-dn'],
            issuerDN: req.headers['x-ssl-client-i-dn'],
            serial: req.headers['x-ssl-client-serial'],
            fingerprint: req.headers['x-ssl-client-fingerprint'],
            commonName: this.extractCommonName(req.headers['x-ssl-client-s-dn'])
        };

        const valid = this.validateCertificate(certInfo);
        
        if (this.logAll) {
            debug('Raw request certificate validation:', { valid, certInfo });
        }

        return { valid, info: certInfo };
    }

    // Add allowed client
    addAllowedClient(commonName) {
        this.allowedClients.add(commonName);
        debug('Added allowed client:', commonName);
    }

    // Remove allowed client
    removeAllowedClient(commonName) {
        this.allowedClients.delete(commonName);
        debug('Removed allowed client:', commonName);
    }

    // Get current configuration
    getConfig() {
        return {
            enabled: this.enabled,
            requireClientCert: this.requireClientCert,
            allowedClients: Array.from(this.allowedClients)
        };
    }
}

export default CertificateAuth;