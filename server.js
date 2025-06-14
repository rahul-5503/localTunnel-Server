import log from 'book';
import Koa from 'koa';
import tldjs from 'tldjs';
import Debug from 'debug';
import http from 'http';
import { hri } from 'human-readable-ids';
import Router from 'koa-router';

import ClientManager from './lib/ClientManager.js';
import CertificateAuth from './lib/CertificateAuth.js';

const debug = Debug('localtunnel:server');

export default function(opt) {
    opt = opt || {};

    const validHosts = (opt.domain) ? [opt.domain] : undefined;
    console.log("validHosts", validHosts);
    const myTldjs = tldjs.fromUserSettings({ validHosts });
    const landingPage = 'https://demo.senzdash.com/Newisenzrwebapp/sign-in ';

    // Initialize certificate authentication
    const certAuth = new CertificateAuth({
        enabled: opt.enableClientCerts || false,
        allowedClients: opt.allowedClients || ['raspberry-pi-client'], // Add your allowed clients
        requireClientCert: opt.requireClientCert !== false,
        logAll: opt.logCertDetails || false
    });

    function GetClientIdFromHostname(hostname) {
        if (hostname.includes('.nip.io')) {
            // Custom logic for nip.io
            const parts = hostname.split('.');
            const subdomainParts = [];
            for (const part of parts) {
                // Stop when part looks like an IP segment
                if (/^\d+$/.test(part)) break;
                subdomainParts.push(part);
            }
            console.log("subpart", subdomainParts);
            return subdomainParts.join('.');
        } else {
            // Fallback to tldjs for standard domains
            console.log("GetClientIdFromHostname", myTldjs.getSubdomain(hostname))
            return myTldjs.getSubdomain(hostname);
        }
    }
    
    const manager = new ClientManager(opt);
    const schema = opt.secure ? 'https' : 'http';
    const app = new Koa();
    const router = new Router();

    // Add certificate authentication middleware to app
    app.use(certAuth.middleware());

    // Add certificate info to requests
    app.use(async (ctx, next) => {
        if (ctx.state.clientCert) {
            console.log('✅ Authenticated client:', ctx.state.clientCert.commonName);
        }
        await next();
    });

    // API Routes with certificate authentication
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

    router.get('/api/tunnels/:id/status', async (ctx, next) => {
        const clientId = ctx.params.id;
        console.log("/api/tunnels", clientId);
        const client = manager.getClient(clientId);
        if (!client) {
            ctx.throw(404);
            return;
        }

        const stats = client.stats();
        ctx.body = {
            connected_sockets: stats.connectedSockets,
            client_cert: ctx.state.clientCert
        };
    });

    // Certificate management API (for managing allowed clients)
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

    // root endpoint
    app.use(async (ctx, next) => {
        console.log("new request /?new")
        const path = ctx.request.path;
        console.log("path", path, ctx.request.host);
        
        // skip anything not on the root path
        if (path !== '/') {
            await next();
            return;
        }
        console.log("new request after path");
        
        const isNewClientRequest = ctx.query['new'] !== undefined;
        console.log("isnewclientrequest", isNewClientRequest);        
        if (isNewClientRequest) {
            const reqId = hri.random();
            
            console.log('making new client with id %s', reqId);
            debug('making new client with id %s', reqId);
            const info = await manager.newClient(reqId);
            const nipIoDomain = 'tunnel.autosecnextgen.com/';            
            const url = 'https' + '://' + info.id + '.' + nipIoDomain;
            info.url = url;
            
            // Add certificate info to response
            if (ctx.state.clientCert) {
                info.client_authenticated = true;
                info.client_name = ctx.state.clientCert.commonName;
            }
            
            ctx.body = info;
            console.log("url", info.url);
            return;
        }

        // no new client request, send to landing page
        ctx.redirect(landingPage);
    });

    // anything after the / path is a request for a specific client name
    app.use(async (ctx, next) => {
        console.log("myappdomain");
        const parts = ctx.request.path.split('/');

        const reqId = parts[1];

        if (!reqId || reqId === 'favicon.ico') {
            await next();
            return;
        }
        console.log("making new client id %s", reqId);
        debug('making new client with id %s', reqId);
        const info = await manager.newClient(reqId);

        const url = schema + '://' + info.id + '.mytunnel';
        info.url = url;
        
        // Add certificate info to response
        if (ctx.state.clientCert) {
            info.client_authenticated = true;
            info.client_name = ctx.state.clientCert.commonName;
        }
        
        ctx.body = info;
        return;
    });
   
    const server = http.createServer();
    const appCallback = app.callback();

    server.on('request', (req, res) => {
        console.log("server client request", req.headers);
        const hostname = req.headers.host;
        if (!hostname) {
            res.statusCode = 400;
            res.end('Host header is required');
            return;
        }

        // Validate client certificate for direct requests
        const certValidation = certAuth.validateRawRequest(req);
        if (!certValidation.valid) {
            console.log('❌ Certificate validation failed for direct request');
            res.statusCode = 401;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
                error: 'Client certificate authentication required',
                details: 'Invalid or missing client certificate'
            }));
            return;
        }

        if (certValidation.info) {
            console.log('✅ Direct request authenticated:', certValidation.info.commonName);
        }

        const clientId = GetClientIdFromHostname(hostname);
        console.log("clientId", clientId);
        if (!clientId) {
            appCallback(req, res);
            return;
        }

        const client = manager.getClient(clientId);
        console.log(client);
        if (!client) {
            res.statusCode = 404;
            res.end('404');
            return;
        }

        client.handleRequest(req, res);
    });

    server.on('upgrade', (req, socket, head) => {
        console.log("server up client request", req.headers);
        const hostname = req.headers.host;
        if (!hostname) {
            socket.destroy();
            return;
        }

        // Validate client certificate for websocket upgrades
        const certValidation = certAuth.validateRawRequest(req);
        if (!certValidation.valid) {
            console.log('❌ Certificate validation failed for websocket upgrade');
            socket.destroy();
            return;
        }

        if (certValidation.info) {
            console.log('✅ Websocket upgrade authenticated:', certValidation.info.commonName);
        }

        const clientId = GetClientIdFromHostname(hostname);
        if (!clientId) {
            socket.destroy();
            return;
        }

        const client = manager.getClient(clientId);
        if (!client) {
            socket.destroy();
            return;
        }

        client.handleUpgrade(req, socket);
    });

    return server;
};