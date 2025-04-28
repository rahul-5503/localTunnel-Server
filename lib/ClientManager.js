import { hri } from 'human-readable-ids';
import Debug from 'debug';

import Client from './Client.js';
import TunnelAgent from './TunnelAgent.js';

// Manage sets of clients
class ClientManager {
    constructor(opt) {
        this.opt = opt || {};

        // id -> client instance
        this.clients = new Map();

        // statistics
        this.stats = {
            tunnels: 0
        };

        this.debug = Debug('lt:ClientManager');

        // no longer needed globally
        // this.graceTimeout = null;
    }

    // create a new tunnel with `id`
    async newClient(id) {
        const clients = this.clients;
        const stats = this.stats;

        // can't ask for id already in use
        if (clients.has(id)) {
            id = hri.random();
        }

        const maxSockets = this.opt.max_tcp_sockets || 10;

        const agent = new TunnelAgent({
            clientId: id,
            maxSockets: maxSockets,
        });

        try {
            const info = await agent.listen();  // start listening ONCE
            agent.port = info.port;             // store port inside agent

            const client = new Client({
                id,
                agent,
            });

            clients.set(id, client); // use Map correctly

            client.once('close', () => {
                this.removeClient(id);
            });

            ++stats.tunnels;

            return {
                id: id,
                port: info.port,
                max_conn_count: maxSockets,
            };
        }
        catch (err) {
            agent.destroy();
            throw err;
        }
    }

    removeClient(id) {
        this.debug('removing client: %s', id);
        const client = this.clients.get(id);
        if (!client) {
            return;
        }
        --this.stats.tunnels;
        this.clients.delete(id);
        client.close();
    }

    hasClient(id) {
        return this.clients.has(id);
    }

    getClient(id) {
        return this.clients.get(id);
    }
}

export default ClientManager;
