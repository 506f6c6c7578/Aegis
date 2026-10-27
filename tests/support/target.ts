import { readFileSync } from "node:fs";
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { connect as connectTcp, Socket } from "node:net";
import { connect as connectTls, createServer as createTlsServer, type TLSSocket } from "node:tls";
import type { SocketConnector } from "@/lib/network/connector";
import type { AddressResolver } from "@/lib/network/resolve";
import type { ScanContext } from "@/services/scanner/context";
import { createHostPinner } from "@/services/scanner/context";

export const testDomain = "aegis-test.fr";
export const publicAddress = "93.184.215.14";

type Certificate = "valid" | "expired" | "self-signed";

function fixture(name: string): Buffer {
    return readFileSync(new URL(`../fixtures/tls/${name}`, import.meta.url));
}

const authority = fixture("ca.crt");

export type Handler = (request: IncomingMessage, response: ServerResponse) => void;

interface TargetOptions {
    certificate?: Certificate;
    https?: Handler;
    http?: Handler | null;
    rawTls?: (socket: TLSSocket) => void;
}

export interface Target {
    connector: SocketConnector;
    contacted: string[];
    close: () => Promise<void>;
}

function listen(server: Server | ReturnType<typeof createTlsServer>): Promise<number> {
    return new Promise((resolve) => {
        server.listen(0, "127.0.0.1", () => {
            const address = server.address();
            resolve(typeof address === "object" && address ? address.port : 0);
        });
    });
}

function refusedSocket(): Socket {
    const socket = new Socket();
    process.nextTick(() => socket.destroy(Object.assign(new Error("Connexion refusée"), { code: "ECONNREFUSED" })));
    return socket;
}

export const secureHeaders = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store"
};

export const respond = (status: number, headers: Record<string, string | string[]> = {}): Handler => (_, response) => {
    response.writeHead(status, headers).end();
};

export const redirectToHttps: Handler = (request, response) => {
    response.writeHead(301, { Location: `https://${request.headers.host ?? testDomain}${request.url ?? "/"}` }).end();
};

export async function startTarget({ certificate = "valid", https = respond(200, secureHeaders), http = redirectToHttps, rawTls }: TargetOptions = {}): Promise<Target> {
    const credentials = { key: fixture(`${certificate}.key`), cert: fixture(`${certificate}.crt`) };
    const secureServer = rawTls ? createTlsServer(credentials, rawTls) : createHttpsServer(credentials, https);
    const plainServer = http ? createHttpServer(http) : null;
    const [httpsPort, httpPort] = await Promise.all([listen(secureServer), plainServer ? listen(plainServer) : Promise.resolve(0)]);
    const contacted: string[] = [];

    const connector: SocketConnector = {
        tcp: ({ host, port }) => {
            contacted.push(`${host}:${port}`);
            return plainServer ? connectTcp({ host: "127.0.0.1", port: httpPort }) : refusedSocket();
        },
        tls: ({ host, port, servername }) => {
            contacted.push(`${host}:${port}`);
            return connectTls({ host: "127.0.0.1", port: httpsPort, servername, ca: [authority], rejectUnauthorized: true, minVersion: "TLSv1.2" });
        }
    };

    const servers = [secureServer, plainServer].filter((server) => server !== null);
    const sockets = new Set<Socket>();
    for (const server of servers) {
        server.on("connection", (socket: Socket) => {
            sockets.add(socket);
            socket.on("close", () => sockets.delete(socket));
        });
    }

    const close = async () => {
        for (const socket of sockets) socket.destroy();
        await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
    };

    return { connector, contacted, close };
}

export function createFakeResolver(records: Record<string, readonly string[] | (() => readonly string[])>): AddressResolver & { lookups: string[] } {
    const lookups: string[] = [];
    const lookup = async (hostname: string) => {
        lookups.push(hostname);
        const record = records[hostname] ?? [];
        return typeof record === "function" ? record() : record;
    };
    return { lookups, resolve4: lookup, resolve6: async () => [] };
}

export function createScanContext(target: Target, resolver: AddressResolver, timeoutMs = 3_000): ScanContext {
    return { connector: target.connector, pinHost: createHostPinner(resolver), deadline: { timeoutMs, signal: AbortSignal.timeout(10_000) } };
}
