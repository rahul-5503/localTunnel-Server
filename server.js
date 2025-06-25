import log from 'book';
import Koa from 'koa';
import tldjs from 'tldjs';
import Debug from 'debug';
import http from 'http';
import { hri } from 'human-readable-ids';
import Router from 'koa-router';
import jwt from 'koa-jwt';
import jwksRsa from 'jwks-rsa';

import ClientManager from './lib/ClientManager.js';
import CertificateAuth from './lib/CertificateAuth.js';

const debug = Debug('localtunnel:server');

export default function(opt) {
    opt = opt || {};

    const validHosts = (opt.domain) ? [opt.domain] : undefined;
    const myTldjs = tldjs.fromUserSettings({ validHosts });
    const landingPage = 'https://demo.senzdash.com/Newisenzrwebapp/sign-in ';

    // IdentityServer4 setup for JWT auth
    const IDENTITY_SERVER_URL = 'https://autosecauthsts.azurewebsites.net';
    const API_AUDIENCE = 'AdministratorClientId_api';

    // JWT middleware setup
    const bearerAuth = jwt({
        secret: jwksRsa.koaJwtSecret({
            cache: true,
            rateLimit: true,
            jwksRequestsPerMinute: 5,
            jwksUri: `${IDENTITY_SERVER_URL}/.well-known/openid-configuration/jwks`,
        }),
        audience: API_AUDIENCE,
        issuer: IDENTITY_SERVER_URL,
        algorithms: ['RS256'],
        passthrough: true // This allows the middleware to continue even if JWT verification fails
    });

    // Enhanced dual authentication middleware
    const dualAuth = async (ctx, next) => {
        let hasValidCert = false;
        let hasValidJWT = false;
        let certError = null;
        let jwtError = null;

        // Check certificate authentication
        if (ctx.state.clientCert && ctx.state.clientCert.verified) {
            hasValidCert = true;
            console.log('✅ Valid certificate authentication for:', ctx.state.clientCert.commonName);
        } else if (ctx.state.clientCert && !ctx.state.clientCert.verified) {
            certError = 'Certificate present but not verified';
        }

        // Check JWT authentication
        try {
            await bearerAuth(ctx, async () => {
                // This inner function runs if JWT is valid
                if (ctx.state.user) {
                    hasValidJWT = true;
                    console.log('✅ Valid JWT authentication for user:', ctx.state.user.sub || ctx.state.user.name || 'unknown');
                }
            });
        } catch (err) {
            jwtError = err.message || 'Invalid JWT token';
            console.log('❌ JWT authentication failed:', jwtError);
        }

        // If either authentication method is valid, proceed
        if (hasValidCert || hasValidJWT) {
            ctx.state.authMethod = hasValidCert ? 'certificate' : 'jwt';
            if (hasValidCert && hasValidJWT) {
                ctx.state.authMethod = 'both';
            }
            return await next();
        }

        // Neither authentication method worked
        const errors = [];
        if (certError) errors.push(`Certificate: ${certError}`);
        if (jwtError) errors.push(`JWT: ${jwtError}`);
        if (!ctx.state.clientCert && !ctx.headers.authorization) {
            errors.push('No certificate or JWT token provided');
        }

        ctx.status = 401;
        ctx.body = {
            error: 'Authentication failed',
            message: 'Valid certificate or JWT token required',
            details: errors,
            authMethods: {
                certificate: hasValidCert,
                jwt: hasValidJWT
            }
        };
    };

    // Certificate-only authentication middleware
    const certOnlyAuth = async (ctx, next) => {
        if (ctx.state.clientCert && ctx.state.clientCert.verified) {
            console.log('✅ Certificate-only authentication for:', ctx.state.clientCert.commonName);
            return await next();
        }

        ctx.status = 401;
        ctx.body = {
            error: 'Certificate authentication required',
            message: 'Valid client certificate required for this endpoint',
            certificatePresent: !!ctx.state.clientCert,
            certificateVerified: ctx.state.clientCert ? ctx.state.clientCert.verified : false
        };
    };

    // JWT-only authentication middleware
    const jwtOnlyAuth = async (ctx, next) => {
        try {
            return await bearerAuth(ctx, next);
        } catch (err) {
            ctx.status = 401;
            ctx.body = {
                error: 'JWT authentication required',
                message: 'Valid JWT Bearer token required for this endpoint',
                details: err.message || 'Invalid or missing JWT token'
            };
        }
    };

    function GetClientIdFromHostname(hostname) {
        if (hostname.includes('.nip.io')) {
            const parts = hostname.split('.');
            const subdomainParts = [];
            for (const part of parts) {
                if (/^\d+$/.test(part)) break;
                subdomainParts.push(part);
            }
            return subdomainParts.join('.');
        } else {
            return myTldjs.getSubdomain(hostname);
        }
    }

    const manager = new ClientManager(opt);
    const schema = opt.secure ? 'https' : 'http';
    const app = new Koa();
    const router = new Router();

    const certAuth = new CertificateAuth({
        enabled: opt.enableClientCerts || false,
        allowedClients: opt.allowedClients || ['raspberry-pi-client'],
        requireClientCert: opt.requireClientCert !== false,
        logAll: opt.logCertDetails || false
    });

    app.use(certAuth.middleware());

    // Enhanced logging middleware
    app.use(async (ctx, next) => {
        const authInfo = [];
        if (ctx.state.clientCert) {
            authInfo.push(`Cert: ${ctx.state.clientCert.commonName} (${ctx.state.clientCert.verified ? 'verified' : 'unverified'})`);
        }
        if (ctx.headers.authorization) {
            authInfo.push('JWT: present');
        }
        if (authInfo.length > 0) {
            console.log('🔐 Authentication info:', authInfo.join(', '));
        }
        await next();
    });

    // Routes with different authentication requirements

    // Route that accepts either certificate OR JWT
    router.get('/api/tunnels/:id/status', dualAuth, async (ctx, next) => {
        const clientId = ctx.params.id;
        const client = manager.getClient(clientId);
        if (!client) {
            ctx.throw(404, 'Tunnel not found');
            return;
        }

        const stats = client.stats();
        ctx.body = {
            connected_sockets: stats.connectedSockets,
            auth_method: ctx.state.authMethod,
            client_cert: ctx.state.clientCert || null,
            jwt_user: ctx.state.user || null,
            timestamp: new Date().toISOString()
        };
    });

    // Route that requires ONLY JWT (for humans/web apps)
    router.get('/api/protected', jwtOnlyAuth, async (ctx, next) => {
        ctx.body = {
            message: '✔️ Valid Bearer Token!',
            user: ctx.state.user,
            auth_method: 'jwt',
            timestamp: new Date().toISOString()
        };
    });

    // Route that requires ONLY certificate (for devices)
    router.get('/api/device/status', certOnlyAuth, async (ctx, next) => {
        ctx.body = {
            message: '✔️ Valid Certificate!',
            client: {
                name: ctx.state.clientCert.commonName,
                verified: ctx.state.clientCert.verified
            },
            auth_method: 'certificate',
            timestamp: new Date().toISOString()
        };
    });

    // Public route that shows authentication status
    router.get('/api/status', async (ctx, next) => {
        const stats = manager.stats;
        ctx.body = {
            tunnels: stats.tunnels,
            mem: process.memoryUsage(),
            authentication: {
                certificate: ctx.state.clientCert ? {
                    name: ctx.state.clientCert.commonName,
                    verified: ctx.state.clientCert.verified
                } : null,
                jwt: ctx.state.user ? {
                    user: ctx.state.user.sub || ctx.state.user.name || 'unknown'
                } : null
            },
            timestamp: new Date().toISOString()
        };
    });

    // Certificate management routes
    router.get('/api/cert/config', async (ctx, next) => {
        ctx.body = certAuth.getConfig();
    });

    router.post('/api/cert/allow/:clientName', certOnlyAuth, async (ctx, next) => {
        const clientName = ctx.params.clientName;
        certAuth.addAllowedClient(clientName);
        ctx.body = { 
            success: true, 
            message: `Client ${clientName} added to allowed list`,
            authorized_by: ctx.state.clientCert.commonName
        };
    });

    // Test endpoints for debugging authentication
    router.get('/api/test/auth', async (ctx, next) => {
        const hasAuth = ctx.headers.authorization;
        const hasCert = ctx.state.clientCert;
        
        ctx.body = {
            message: 'Authentication test endpoint',
            authorization_header_present: !!hasAuth,
            certificate_present: !!hasCert,
            certificate_verified: hasCert ? hasCert.verified : false,
            certificate_name: hasCert ? hasCert.commonName : null,
            headers: {
                authorization: hasAuth ? 'Bearer [REDACTED]' : null,
                host: ctx.headers.host,
                'user-agent': ctx.headers['user-agent']
            }
        };
    });

    app.use(router.routes());
    app.use(router.allowedMethods());

    // Client request: /?new
    app.use(async (ctx, next) => {
        const path = ctx.request.path;
        if (path !== '/') {
            await next();
            return;
        }

        const isNewClientRequest = ctx.query['new'] !== undefined;
        if (isNewClientRequest) {
            const reqId = hri.random();
            const info = await manager.newClient(reqId);
            const nipIoDomain = 'tunnel.autosecnextgen.com/';
            const url = 'https://' + info.id + '.' + nipIoDomain;
            info.url = url;

            if (ctx.state.clientCert) {
                info.client_authenticated = true;
                info.client_name = ctx.state.clientCert.commonName;
            }

            if (ctx.state.user) {
                info.jwt_authenticated = true;
                info.jwt_user = ctx.state.user.sub || ctx.state.user.name || 'unknown';
            }

            ctx.body = info;
            return;
        }

        ctx.redirect(landingPage);
    });

    // /tunnelid route
    app.use(async (ctx, next) => {
        const parts = ctx.request.path.split('/');
        const reqId = parts[1];
        if (!reqId || reqId === 'favicon.ico') {
            await next();
            return;
        }

        const info = await manager.newClient(reqId);
        const url = schema + '://' + info.id + '.mytunnel';
        info.url = url;

        if (ctx.state.clientCert) {
            info.client_authenticated = true;
            info.client_name = ctx.state.clientCert.commonName;
        }

        if (ctx.state.user) {
            info.jwt_authenticated = true;
            info.jwt_user = ctx.state.user.sub || ctx.state.user.name || 'unknown';
        }

        ctx.body = info;
    });

    const server = http.createServer();
    const appCallback = app.callback();

    server.on('request', (req, res) => {
        const hostname = req.headers.host;
        if (!hostname) {
            res.statusCode = 400;
            res.end('Host header is required');
            return;
        }

        const clientId = GetClientIdFromHostname(hostname);
        
        // Only manually handle if clientId is present (tunnel request)
        if (clientId) {
            if (opt.enableClientCerts && opt.requireClientCert) {
                const clientCertVerify = req.headers['x-ssl-client-verify'];
                const clientCertSubject = req.headers['x-ssl-client-s-dn'];

                if (clientCertVerify !== 'SUCCESS' || !clientCertSubject) {
                    res.statusCode = 401;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({
                        error: 'Client certificate not verified by NGINX',
                        details: clientCertVerify || 'No verification result',
                        certificate_verify: clientCertVerify,
                        certificate_subject: clientCertSubject
                    }));
                    return;
                }
            }

            const client = manager.getClient(clientId);
            if (!client) {
                res.statusCode = 404;
                res.end('Tunnel not found');
                return;
            }

            client.handleRequest(req, res);
        } else {
            // Let Koa (and authentication middlewares) handle API routes
            appCallback(req, res);
        }
    });

    server.on('upgrade', (req, socket, head) => {
        const hostname = req.headers.host;
        if (!hostname) {
            socket.destroy();
            return;
        }

        // Apply same optional certificate check here
        if (opt.enableClientCerts && opt.requireClientCert) {
            const clientCertVerify = req.headers['x-ssl-client-verify'];
            const clientCertSubject = req.headers['x-ssl-client-s-dn'];

            if (clientCertVerify !== 'SUCCESS' || !clientCertSubject) {
                socket.destroy();
                return;
            }
        }

        const clientId = GetClientIdFromHostname(hostname);
        const client = manager.getClient(clientId);
        if (!client) {
            socket.destroy();
            return;
        }

        client.handleUpgrade(req, socket);
    });

    return server;
};