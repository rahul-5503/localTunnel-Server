import http from 'http';
import Debug from 'debug';
import pump from 'pump';
import EventEmitter from 'events';

class Client extends EventEmitter {
    constructor(options) {
        super();

        const agent = this.agent = options.agent;
        const id = this.id = options.id;

        this.debug = Debug(`lt:Client[${this.id}]`);
        console.log(`[Client] Created: ${this.id}`);

        // client is given a grace period in which they can connect before they are _removed_
        this.graceTimeout = setTimeout(() => {
            console.log(`[Client] Grace timeout expired, closing: ${this.id}`);
            this.close();
        }, 5000).unref();

        agent.on('online', () => {
            this.debug('client online %s', id);
            console.log(`[Client] Online: ${id}`);
            clearTimeout(this.graceTimeout);
        });

        agent.on('offline', () => {
            this.debug('client offline %s', id);
            console.log(`[Client] Offline: ${id}`);
            clearTimeout(this.graceTimeout);
            this.graceTimeout = setTimeout(() => {
                console.log(`[Client] Grace timeout after offline, closing: ${this.id}`);
                this.close();
            }, 1000).unref();
        });

        agent.once('error', (err) => {
            console.log(`[Client] Agent error for ${this.id}:`, err.message);
            this.close();
        });
    }

    stats() {
        return this.agent.stats();
    }

    close() {
        clearTimeout(this.graceTimeout);
        this.agent.destroy();
        console.log(`[Client] Closed: ${this.id}`);
        this.emit('close');
    }

    handleRequest(req, res) {
        this.debug('> %s', req.url);
        console.log(`[Client] Handling HTTP request for ${this.id}: ${req.method} ${req.url}`);

        const opt = {
            path: req.url,
            agent: this.agent,
            method: req.method,
            headers: req.headers
        };

        const clientReq = http.request(opt, (clientRes) => {
            this.debug('< %s', req.url);
            res.writeHead(clientRes.statusCode, clientRes.headers);
            pump(clientRes, res);
        });

        clientReq.once('error', (err) => {
            console.log(`[Client] HTTP request error for ${this.id}:`, err.message);
        });

        pump(req, clientReq);
    }

    handleUpgrade(req, socket) {
        this.debug('> [up] %s', req.url);
        console.log(`[Client] Handling upgrade request for ${this.id}: ${req.url}`);

        socket.once('error', (err) => {
            if (err.code == 'ECONNRESET' || err.code == 'ETIMEDOUT') {
                return;
            }
            console.error(`[Client] Socket error on upgrade:`, err);
        });

        this.agent.createConnection({}, (err, conn) => {
            this.debug('< [up] %s', req.url);
            if (err) {
                console.log(`[Client] Failed to create connection for upgrade: ${err.message}`);
                socket.end();
                return;
            }

            if (!socket.readable || !socket.writable) {
                console.log(`[Client] Socket no longer readable/writable during upgrade: ${this.id}`);
                conn.destroy();
                socket.end();
                return;
            }

            const arr = [`${req.method} ${req.url} HTTP/${req.httpVersion}`];
            for (let i = 0; i < (req.rawHeaders.length - 1); i += 2) {
                arr.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
            }

            arr.push('');
            arr.push('');

            pump(conn, socket);
            pump(socket, conn);
            conn.write(arr.join('\r\n'));
        });
    }
}

export default Client;
