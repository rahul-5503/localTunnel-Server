import Koa from 'koa';
import Router from 'koa-router';
import http from 'http';
import tldjs from 'tldjs';
import Debug from 'debug';
import { hri } from 'human-readable-ids';
import jwt from 'koa-jwt';
import jwksRsa from 'jwks-rsa';

import ClientManager from './lib/ClientManager.js';
import CertificateAuth from './lib/CertificateAuth.js';

const debug = Debug('localtunnel:server');

export default function (opt = {}) {
    const app = new Koa();
    const router = new Router();
    const validHosts = opt.domain ? [opt.domain] : undefined;
    const myTldjs = tldjs.fromUserSettings({ validHosts });
    const landingPage = 'https://demo.senzdash.com/Newisenzrwebapp/sign-in';

    const manager = new ClientManager(opt);
    const schema = opt.secure ? 'https' : 'http';

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

    const certAuth = new CertificateAuth({
        enabled: opt.enableClientCerts || false,
        allowedClients: opt.allowedClients || ['raspberry-pi-client'],
        requireClientCert: false, // Let dual auth control this
        logAll: opt.logCertDetails || false
    });

    app.use(certAuth.middleware());

    const dualAuth = async (ctx, next) => {
        if (ctx.state.clientCert) {
            console.log('✅ Client authenticated via certificate:', ctx.state.clientCert.commonName);
            return next();
        }

        try {
            await bearerAuth(ctx, next);
            console.log('✅ Client authenticated via JWT:', ctx.state.user?.client_id || ctx.state.user?.sub);
        } catch (err) {
            ctx.status = 401;
            ctx.body = {
                error: 'Unauthorized',
                message: 'Client must authenticate with a valid certificate or bearer token.'
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

    router.get('/api/status', async (ctx) => {
        ctx.body = {
            tunnels: manager.stats.tunnels,
            mem: process.memoryUsage(),
            authenticated: ctx.state.clientCert
                ? { method: 'cert', subject: ctx.state.clientCert.commonName }
                : ctx.state.user
                    ? { method: 'jwt', subject: ctx.state.user.client_id || ctx.state.user.sub }
                    : null
        };
    });

    // Route protected by cert or JWT
    router.get('/api/tunnels/:id/status', dualAuth, async (ctx) => {
        const clientId = ctx.params.id;
        const client = manager.getClient(clientId);
        if (!client) {
            ctx.throw(404);
            return;
        }

        const stats = client.stats();
        ctx.body = {
            connected_sockets: stats.connectedSockets,
            authenticated: ctx.state.clientCert
                ? { method: 'cert', subject: ctx.state.clientCert.commonName }
                : { method: 'jwt', subject: ctx.state.user.client_id || ctx.state.user.sub }
        };
    });

    app.use(router.routes());
    app.use(router.allowedMethods());

    // Create tunnel request (?new)
    app.use(async (ctx, next) => {
        if (ctx.path !== '/') {
            await next();
            return;
        }

        const isNewClientRequest = ctx.query['new'] !== undefined;
        if (!isNewClientRequest) {
            ctx.redirect(landingPage);
            return;
        }

        if (!ctx.state.clientCert && !ctx.state.user) {
            ctx.status = 401;
            ctx.body = {
                error: 'Unauthorized',
                message: 'Provide a valid certificate or bearer token to request a new tunnel.'
            };
            return;
        }

        const reqId = hri.random();
        const info = await manager.newClient(reqId);
        const nipIoDomain = opt.domain || 'tunnel.autosecnextgen.com';
        info.url = `https://${info.id}.${nipIoDomain}/`;

        if (ctx.state.clientCert) {
            info.client_authenticated = true;
            info.client_name = ctx.state.clientCert.commonName;
        }

        if (ctx.state.user) {
            info.client_authenticated = true;
            info.client_name = ctx.state.user.client_id || ctx.state.user.sub;
        }

        ctx.body = info;
    });

    const server = http.createServer(app.callback());

    server.on('request', (req, res) => {
        const hostname = req.headers.host;
        if (!hostname) {
            res.statusCode = 400;
            res.end('Host header is required');
            return;
        }

        const clientId = GetClientIdFromHostname(hostname);
        const client = manager.getClient(clientId);
        if (!client) {
            res.statusCode = 404;
            res.end('Tunnel not found');
            return;
        }

        client.handleRequest(req, res);
    });

    server.on('upgrade', (req, socket) => {
        const hostname = req.headers.host;
        const clientId = GetClientIdFromHostname(hostname);
        const client = manager.getClient(clientId);
        if (!client) {
            socket.destroy();
            return;
        }

        client.handleUpgrade(req, socket);
    });

    return server;
}
