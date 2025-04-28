import httpProxy from 'http-proxy';
import EventEmitter from 'events';

class Client extends EventEmitter {
    constructor({ id, agent }) {
        super();
        this.id = id;
        this.agent = agent;

        this.proxy = httpProxy.createProxyServer({
            agent: this.agent,
            ws: true,
            preserveHeaderKeyCase: true,
            xfwd: true,
        });

        this.proxy.on('error', (err, req, res) => {
            if (res.writeHead && !res.headersSent) {
                res.writeHead(502);
            }
            if (res.end) {
                res.end('Bad Gateway');
            }
        });

        // this.graceTimeout = setTimeout(() => {
        //     console.log("closetime");
        //     this.close();
        // }, 1000).unref();

        agent.on('online', () => {
            console.log("onlinetime");
            clearTimeout(this.graceTimeout);
        });

        agent.on('offline', () => {
            clearTimeout(this.graceTimeout);
            this.graceTimeout = setTimeout(() => {
                console.log("ofilnegraceTime");
                this.close();
            }, 1000).unref();
        });

        agent.once('error', () => {
            console.log("errorclose");
            this.close();
        });
    }

    stats() {
        return this.agent.stats();
    }

    close() {
        console.log("closetimeout");
        clearTimeout(this.graceTimeout);
        this.agent.destroy();
        this.emit('close');
    }

    handleRequest(req, res) {
        const target = `http://127.0.0.1:${this.agent.port}`;

        // disable timeouts for live streaming
        req.setTimeout(0);
        res.setTimeout(0);
        if (req.socket) req.socket.setTimeout(0);
        if (res.socket) res.socket.setTimeout(0);
        console.log("request");
        this.proxy.web(req, res, { target });
    }

    handleUpgrade(req, socket, head) {
        const target = `http://127.0.0.1:${this.agent.port}`;

        if (req.socket) req.socket.setTimeout(0);

        this.proxy.ws(req, socket, head, { target });
    }
}

export default Client;
