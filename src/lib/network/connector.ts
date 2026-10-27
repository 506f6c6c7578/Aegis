import { connect as connectTcp, type Socket } from "node:net";
import { connect as connectTls, type TLSSocket } from "node:tls";
import { assertPublicAddress, type PinnedHost } from "@/lib/network/resolve";

export const allowedPorts = { http: 80, https: 443 } as const;

interface SocketOptions {
    host: string;
    port: number;
    family: 4 | 6;
}

interface TlsSocketOptions extends SocketOptions {
    servername: string;
}

export interface SocketConnector {
    tcp: (options: SocketOptions) => Socket;
    tls: (options: TlsSocketOptions) => TLSSocket;
}

export const systemConnector: SocketConnector = {
    tcp: (options) => connectTcp(options),
    tls: (options) => connectTls({
        ...options,
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
        ALPNProtocols: ["http/1.1"]
    })
};

function ignoreLateError(): void {}

function guard<Connection extends Socket>(socket: Connection): Connection {
    socket.on("error", ignoreLateError);
    return socket;
}

function toSocketOptions({ address, family }: PinnedHost, port: number): SocketOptions {
    return { host: assertPublicAddress(address), port, family };
}

export function openPlainSocket(connector: SocketConnector, host: PinnedHost): Socket {
    return guard(connector.tcp(toSocketOptions(host, allowedPorts.http)));
}

export function openTlsSocket(connector: SocketConnector, host: PinnedHost): TLSSocket {
    return guard(connector.tls({ ...toSocketOptions(host, allowedPorts.https), servername: host.hostname }));
}
