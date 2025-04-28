import log from 'book';
import Koa from 'koa';
import tldjs from 'tldjs';
import Debug from 'debug';
import http from 'http';
import { hri } from 'human-readable-ids';
import Router from 'koa-router';

import ClientManager from './lib/ClientManager.js';

const debug = Debug('localtunnel:server');

export default function(opt) {
    opt = opt || {};

    const validHosts = (opt.domain) ? [opt.domain] : undefined;
    console.log("validHosts",validHosts);
    const myTldjs = tldjs.fromUserSettings({ validHosts });
    const landingPage = 'https://demo.senzdash.com/Newisenzrwebapp/sign-in ';

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
            console.log("subpart",subdomainParts);
            return subdomainParts.join('.');
        } else {
            // Fallback to tldjs for standard domains
            return myTldjs.getSubdomain(hostname);
        }
    }
    

    // function GetClientIdFromHostname(hostname) {
    //     // Example: 'blue-puma-69.192.168.1.3.nip.io'
    //     const parts = hostname.split('.');
    //     console.log('hostname',hostname);
    //     const subdomainParts = [];
    //     for (const part of parts) {
    //         // Stop collecting when part is an IP segment
    //         if (/^\d+$/.test(part)) break;
    //         subdomainParts.push(part);
    //     }
    
    //     return subdomainParts.join('.');
    // }
    
    const manager = new ClientManager(opt);

    const schema = opt.secure ? 'https' : 'http';

    const app = new Koa();
    const router = new Router();

    router.get('/api/status', async (ctx, next) => {
        const stats = manager.stats;
        ctx.body = {
            tunnels: stats.tunnels,
            mem: process.memoryUsage(),
        };
    });

    router.get('/api/tunnels/:id/status', async (ctx, next) => {
        const clientId = ctx.params.id;
        console.log("/api/tunnels",clientId);
        const client = manager.getClient(clientId);
        if (!client) {
            ctx.throw(404);
            return;
        }

        const stats = client.stats();
        ctx.body = {
            connected_sockets: stats.connectedSockets,
        };
    });

    app.use(router.routes());
    app.use(router.allowedMethods());

    // root endpoint
    app.use(async (ctx, next) => {
        console.log("new request /?new")
        const path = ctx.request.path;
     console.log("path",path, ctx.request.host);
     
        // skip anything not on the root path
        if (path !== '/') {
            await next();
            return;
        }
 console.log("new request after path");
 
        const isNewClientRequest = ctx.query['new'] !== undefined;
        console.log("isnewclientrequest",isNewClientRequest);        
        if (isNewClientRequest) {
            const reqId = hri.random();
            console.log('making new client with id %s', reqId);
            debug('making new client with id %s', reqId);
            const info = await manager.newClient(reqId);
            const nipIoDomain = '192.168.1.5.nip.io';
            const url= 'http://'+info.id+'.'+nipIoDomain;
           //const url = schema + '://' + info.id + '.' + ctx.request.host;
           // const url = schema + '://' +info.id+'.192.168.1.3' + '.' + 'loca.lt';
            info.url = url;
            ctx.body = info;
            console.log("url",info.url);
            
            return;
        }

        // no new client request, send to landing page
        ctx.redirect(landingPage);
    });

    // anything after the / path is a request for a specific client name
    // This is a backwards compat feature
    app.use(async (ctx, next) => {
        console.log("myappdomain");
        const parts = ctx.request.path.split('/');

        // any request with several layers of paths is not allowed
        // rejects /foo/bar
        // allow /foo
        // if (parts.length !== 2) {
        //     await next();
        //     return;
        // }

        const reqId = parts[1];

        // limit requested hostnames to 63 characters
        // if (! /^(?:[a-z0-9][a-z0-9\-]{4,63}[a-z0-9]|[a-z0-9]{4,63})$/.test(reqId)) {
        //     const msg = 'Invalid subdomain. Subdomains must be lowercase and between 4 and 63 alphanumeric characters.';
        //     ctx.status = 403;
        //     ctx.body = {
        //         message: msg,
        //     };
        //     return;
        // }
        if (!reqId || reqId === 'favicon.ico') {
            await next();
            return;
        }
        console.log("making new client id %s", reqId);
        debug('making new client with id %s', reqId);
        const info = await manager.newClient(reqId);

        const url = schema + '://' + info.id + '.mytunnel';
        info.url = url;
        ctx.body = info;
        return;
    });

    const server = http.createServer();

    const appCallback = app.callback();

    server.on('request', (req, res) => {
        // without a hostname, we won't know who the request is for
       console.log("server client request",req.headers);
        const hostname = req.headers.host;
        if (!hostname) {
            res.statusCode = 400;
            res.end('Host header is required');
            return;
        }

        const clientId = GetClientIdFromHostname(hostname);
        if (!clientId) {
            appCallback(req, res);
            return;
        }

         const client = manager.getClient(clientId);
        // console.log(client);
        if (!client) {
            res.statusCode = 404;
            res.end('404');
            return;
        }

        client.handleRequest(req, res);
    });

    server.on('upgrade', (req, socket, head) => {
        console.log("server up client request",req.headers);
        const hostname = req.headers.host;
        if (!hostname) {
            socket.destroy();
            return;
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
