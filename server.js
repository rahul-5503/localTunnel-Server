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
    });

    const dualAuth = async (ctx, next) => {
        if (ctx.state.clientCert) return next();
        try {
            return await bearerAuth(ctx, next);
        } catch (err) {
            ctx.status = 401;
            ctx.body = { error: 'Unauthorized - No valid cert or bearer token' };
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

    app.use(async (ctx, next) => {
        if (ctx.state.clientCert) {
            console.log('✅ Authenticated client (cert):', ctx.state.clientCert.commonName);
        }
        await next();
    });

    // Protected route using either cert or bearer
    router.get('/api/tunnels/:id/status', dualAuth, async (ctx, next) => {
        const clientId = ctx.params.id;
        const client = manager.getClient(clientId);
        if (!client) {
            ctx.throw(404);
            return;
        }

        const stats = client.stats();
        ctx.body = {
            connected_sockets: stats.connectedSockets,
            client_cert: ctx.state.clientCert || null,
            jwt_user: ctx.state.user || null
        };
    });

    // Protected route - bearer only
    router.get('/api/protected', bearerAuth, async (ctx, next) => {
        ctx.body = {
            message: '✔️ Valid Bearer Token!',
            user: ctx.state.user
        };
    });

    router.get('/api/status', async (ctx, next) => {
        const stats = manager.stats;
        ctx.body = {
            tunnels: stats.tunnels,
            mem: process.memoryUsage(),
            client: ctx.state.clientCert ? {
                name: ctx.state.clientCert.commonName,
                verified: ctx.state.clientCert.verified
            } : null
        };
    });

    router.get('/api/cert/config', async (ctx, next) => {
        ctx.body = certAuth.getConfig();
    });

    router.post('/api/cert/allow/:clientName', async (ctx, next) => {
        const clientName = ctx.params.clientName;
        certAuth.addAllowedClient(clientName);
        ctx.body = { success: true, message: `Client ${clientName} added to allowed list` };
    });

    app.use(router.routes());
    app.use(router.allowedMethods());

    // Client request: /?new
    // app.use(async (ctx, next) => {
    //     const path = ctx.request.path;
    //     if (path !== '/') {
    //         await next();
    //         return;
    //     }

    //     const isNewClientRequest = ctx.query['new'] !== undefined;
    //     if (isNewClientRequest) {
    //         const reqId = hri.random();
    //         const info = await manager.newClient(reqId);
    //         const nipIoDomain = 'tunnel.autosecnextgen.com/';
    //         const url = 'https://' + info.id + '.' + nipIoDomain;
    //         info.url = url;

    //         if (ctx.state.clientCert) {
    //             info.client_authenticated = true;
    //             info.client_name = ctx.state.clientCert.commonName;
    //         }

    //         ctx.body = info;
    //         return;
    //     }

    //     ctx.redirect(landingPage);
    // });

    // Client request: /?new
app.use(async (ctx, next) => {
    const path = ctx.request.path;
    if (path !== '/') {
        await next();
        return;
    }

    const isNewClientRequest = ctx.query['new'] !== undefined;

    if (isNewClientRequest) {
        const hasCert = ctx.state.clientCert && ctx.state.clientCert.verified;
        const hasJWT = ctx.state.user != null;

        if (!hasCert && !hasJWT) {
            ctx.status = 401;
            ctx.body = {
                error: 'Unauthorized',
                message: 'You must provide a valid client certificate or bearer token.'
            };
            return;
        }

        const reqId = hri.random();
        const info = await manager.newClient(reqId);
        const nipIoDomain = 'tunnel.autosecnextgen.com/';
        const url = 'https://' + info.id + '.' + nipIoDomain;
        info.url = url;

        if (hasCert) {
            info.client_authenticated = true;
            info.client_name = ctx.state.clientCert.commonName;
        } else if (hasJWT) {
            info.client_authenticated = true;
            info.client_name = ctx.state.user.client_id || ctx.state.user.sub;
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
                    details: clientCertVerify || 'No verification result'
                }));
                return;
            }
        }

        const client = manager.getClient(clientId);
        if (!client) {
            res.statusCode = 404;
            res.end('404');
            return;
        }

        client.handleRequest(req, res);
    } else {
        // Let Koa (and koa-jwt) handle normal routes like /api/protected
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
