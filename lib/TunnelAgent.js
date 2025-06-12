import { Agent } from 'http';
import net from 'net';
import log from 'book';
import Debug from 'debug';

const DEFAULT_MAX_SOCKETS = 10;

class TunnelAgent extends Agent {
    constructor(options = {}) {
        super({
            keepAlive: true,
            maxFreeSockets: 1,
        });

        this.availableSockets = [];
        this.waitingCreateConn = [];

        this.debug = Debug(`lt:TunnelAgent[${options.clientId}]`);
        this.connectedSockets = 0;
        this.maxTcpSockets = options.maxTcpSockets || DEFAULT_MAX_SOCKETS;

        this.server = net.createServer();
        this.started = false;
        this.closed = false;
    }

    stats() {
        return {
            connectedSockets: this.connectedSockets,
        };
    }

    listen() {
        const server = this.server;
        if (this.started) {
            throw new Error('already started');
        }
        this.started = true;

        server.on('close', this._onClose.bind(this));
        server.on('connection', this._onConnection.bind(this));
        server.on('error', (err) => {
            if (err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT') return;
            log.error(err);
        });

        // Port range restriction
        const minPort = 49000;
        const maxPort = 65000;

        function getRandomPort(min, max) {
            return Math.floor(Math.random() * (max - min + 1)) + min;
        }

        return new Promise((resolve, reject) => {
            const tryListen = (retries = 10) => {
                if (retries <= 0) {
                    return reject(new Error('Could not bind to a port in range 50000–65000'));
                }

                const port = getRandomPort(minPort, maxPort);

                const onError = (err) => {
                    if (err.code === 'EADDRINUSE' || err.code === 'EACCES') {
                        server.removeListener('error', onError);
                        tryListen(retries - 1);
                    } else {
                        reject(err);
                    }
                };

                server.once('error', onError);

                server.listen(port, () => {
                    server.removeListener('error', onError);
                    this.debug('tcp server listening on port: %d', port);
                    console.log(`Server listening on: ${port}`);
                    resolve({ port });
                });
            };
            
            tryListen();
        });
    }

    _onClose() {
        this.closed = true;
        this.debug('closed tcp socket');
        for (const conn of this.waitingCreateConn) {
            conn(new Error('closed'), null);
        }
        this.waitingCreateConn = [];
        this.emit('end');
    }

    _onConnection(socket) {
        if (this.connectedSockets >= this.maxTcpSockets) {
            this.debug('no more sockets allowed');
            socket.destroy();
            return false;
        }

        socket.once('close', (hadError) => {
            this.debug('closed socket (error: %s)', hadError);
            this.connectedSockets -= 1;
            const idx = this.availableSockets.indexOf(socket);
            if (idx >= 0) {
                this.availableSockets.splice(idx, 1);
            }

            this.debug('connected sockets: %s', this.connectedSockets);
            if (this.connectedSockets <= 0) {
                this.debug('all sockets disconnected');
                this.emit('offline');
            }
        });

        socket.once('error', () => {
            socket.destroy();
        });

        if (this.connectedSockets === 0) {
            this.emit('online');
        }

        this.connectedSockets += 1;
        this.debug('new connection from: %s:%s', socket.address().address, socket.address().port);

        const fn = this.waitingCreateConn.shift();
        if (fn) {
            this.debug('giving socket to queued conn request');
            setTimeout(() => fn(null, socket), 0);
            return;
        }

        this.availableSockets.push(socket);
    }

    createConnection(options, cb) {
        if (this.closed) {
            cb(new Error('closed'));
            return;
        }

        this.debug('create connection');

        const sock = this.availableSockets.shift();

        if (!sock) {
            this.waitingCreateConn.push(cb);
            this.debug('waiting connected: %s', this.connectedSockets);
            this.debug('waiting available: %s', this.availableSockets.length);
            return;
        }

        this.debug('socket given');
        cb(null, sock);
    }

    destroy() {
        this.server.close();
        super.destroy();
    }
}

export default TunnelAgent;
