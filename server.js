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
   
    const jwtAuth = jwt({
    secret: jwksRsa.koaJwtSecret({
        jwksUri: 'https://autosecauthsts.azurewebsites.net/.well-known/openid-configuration/jwks',
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5
    }),
    audience: 'AdministratorClientId_api', 
    issuer: 'https://autosecauthsts.azurewebsites.net',
    algorithms: ['RS256'],
    passthrough: true ,
     getToken: (ctx) => {
        if (ctx.path.startsWith('/video-feed/')) {   
            console.log("/video-feed",ctx.query.token);         
            return ctx.query.token;
        }
        
        if (ctx.headers.authorization && ctx.headers.authorization.startsWith('Bearer ')) {
            return ctx.headers.authorization.split(' ')[1];
        }

        return null;
    }
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

    app.use(jwtAuth);

    router.get('/api/userinfo', async (ctx) => {
    if (ctx.state.user) {
        ctx.body = {
            authenticated: true,
            jwtUser: ctx.state.user
        };
    } else {
        ctx.status = 401;
        ctx.body = { error: 'JWT required' };
    }
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

    
app.use(async (ctx, next) => {
    // if (ctx.path.startsWith('/video-feed/')) {
    //     console.log('⚠ Skipping middleware for video stream path');
    //     await next();
    //     return; // avoid Koa processing
    // }
    const jwtUser = ctx.state.user;
    const certUser = ctx.state.clientCert;

    if (certUser) {
        console.log(`✅ Cert Auth: ${certUser.commonName}`);
    } else if (jwtUser) {
        console.log(`✅ JWT Auth: ${jwtUser.sub}`);
    } else {
        console.log('❌ No valid authentication found');
        ctx.status = 401;
        ctx.body = { error: 'Authentication required (cert or JWT)' };
        return;
    }

    await next();
});



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
        res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*'|| 'localhost' ||'https://black-forest-0273ca000.5.azurestaticapps.net');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        if (req.method === 'OPTIONS') {
            res.statusCode = 204;
            res.end();
            return;
        }
 
        const hostname = req.headers.host;
        if (!hostname) {
            res.statusCode = 400;
            res.end('Host header is required');
            return;
        }
        const clientCertVerify = req.headers['x-ssl-client-verify'];
        const clientCertSubject = req.headers['x-ssl-client-s-dn'];
        const authHeader = req.headers['authorization'];

        const hasCert = clientCertVerify === 'SUCCESS' && clientCertSubject;
        const hasJWT = !!authHeader && authHeader.startsWith('Bearer ');

        // if (req.url.startsWith('/video-feed/')) {
        //     console.log('🔓 Bypassing auth for video feed stream:', req.url);
        //} else
         if (!hasCert && !hasJWT) {
                const rawHeaders = JSON.stringify(req.headers, null, 2);
                console.warn('❌ No valid certificate or JWT provided');
                if (!req.headers['authorization']) {
                    console.warn('🕵️ No Authorization header in request');
                } else {
                    console.warn('🛑 Auth header found but malformed:', req.headers['authorization']);
                }
                console.warn(rawHeaders);
                res.statusCode = 401;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({
                    error: 'Client certificate or Bearer token required',
                    certVerify: clientCertVerify || 'missing',
                    jwt: !!authHeader ? 'provided' : 'missing'
            }));
            return;
        }


        if (hasCert) {
            console.log(`✅ Client certificate verified: ${clientCertSubject}`);
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
                // Trust certificate info from NGINX headersconst clientCertVerify = req.headers['x-ssl-client-verify'];
        const clientCertSubject = req.headers['x-ssl-client-s-dn'];

        if (clientCertVerify !== 'SUCCESS' || !clientCertSubject) {
            console.log('❌ Client certificate verification failed or missing from headers');
            res.statusCode = 401;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
                error: 'Client certificate not verified by NGINX',
                details: clientCertVerify || 'No verification result'
            }));
            return;
        }

        console.log(`✅ Client certificate verified: ${clientCertSubject}`);



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