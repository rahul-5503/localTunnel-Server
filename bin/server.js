#!/usr/bin/env node -r esm

import optimist from 'optimist';
import log from 'book';
import Debug from 'debug';
import CreateServer from '../server.js';

const debug = Debug('localtunnel');

const argv = optimist
    .usage('Usage: $0 --port [num]')
    .options('secure', {
        default: false,
        describe: 'use this flag to indicate proxy over https'
    })
    .options('port', {
        default: '3000',
        describe: 'listen on this port for outside requests'
    })
    .options('address', {
        default: '0.0.0.0',
        describe: 'IP address to bind to'
    })
    .options('domain', {
        default: 'azurewebsites.net',
        describe: 'Specify the base domain name. This is optional if hosting localtunnel from a regular example.com domain. This is required if hosting a localtunnel server from a subdomain (i.e. lt.example.dom where clients will be client-app.lt.example.come)',
    })
    .options('max-sockets', {
        default: 10,
        describe: 'maximum number of tcp sockets each client is allowed to establish at one time (the tunnels)'
    })
    .options('enable-client-certs', {
        default: false,
        describe: 'enable client certificate authentication'
    })
    .options('require-client-cert', {
        default: false,
        describe: 'require client certificate for all requests (only applies when enable-client-certs is true)'
    })
    .options('allowed-clients', {
        default: 'raspberry-pi-client',
        describe: 'comma-separated list of allowed client certificate common names'
    })
    .options('log-cert-details', {
        default: false,
        describe: 'log detailed certificate information for debugging'
    })
    .argv;

if (argv.help) {
    optimist.showHelp();
    process.exit();
}

// Parse allowed clients
const allowedClients = argv['allowed-clients'] ? 
    argv['allowed-clients'].split(',').map(name => name.trim()) : 
    ['raspberry-pi-client'];

console.log('🔐 Certificate Authentication Configuration:');
console.log('  Enabled:', argv['enable-client-certs']);
console.log('  Required:', argv['require-client-cert']);
console.log('  Allowed clients:', allowedClients);

const server = CreateServer({
    max_tcp_sockets: argv['max-sockets'],
    secure: argv.secure,
    domain: argv.domain,
    enableClientCerts: argv['enable-client-certs'],
    requireClientCert: argv['require-client-cert'],
    allowedClients: allowedClients,
    logCertDetails: argv['log-cert-details']
});

const port = process.env.PORT || argv.port || 3000;
server.listen(port, argv.address, () => {
    console.log("🚀 Server running with certificate authentication");
    console.log('📡 Server listening on port: %d', server.address().port);
    debug('server listening on port: %d', server.address().port);
});

process.on('SIGINT', () => {
    process.exit();
});

process.on('SIGTERM', () => {
    process.exit();
});

process.on('uncaughtException', (err) => {
    log.error(err);
});

process.on('unhandledRejection', (reason, promise) => {
    log.error(reason);
});