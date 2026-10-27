import { request as createRequest, type IncomingMessage } from "node:http";
import { site } from "@/data/site";
import type { HeaderMap, HttpProbe } from "@/domain/audit/model";
import { openPlainSocket, openTlsSocket, type SocketConnector } from "@/lib/network/connector";
import { NetworkError, toNetworkError } from "@/lib/network/errors";
import type { PinnedHost } from "@/lib/network/resolve";
import type { Deadline } from "@/lib/network/socket";

const maxHeaderSize = 32 * 1024;
const maxHeaderCount = 120;
const maxHeaderValueLength = 8 * 1024;
const maxDocumentHeadBytes = 64 * 1024;

export interface HttpRequest {
    url: URL;
    host: PinnedHost;
    method: HttpProbe["method"];
}

export function toHeaderMap(rawHeaders: readonly string[]): HeaderMap {
    const headers = new Map<string, string[]>();
    for (let index = 0; index + 1 < rawHeaders.length && index < maxHeaderCount * 2; index += 2) {
        const name = rawHeaders[index]?.toLowerCase() ?? "";
        const value = rawHeaders[index + 1]?.slice(0, maxHeaderValueLength) ?? "";
        headers.set(name, [...(headers.get(name) ?? []), value]);
    }
    return headers;
}

type ResponseReader<Output> = (response: IncomingMessage, finish: (output: Output) => void, fail: (error: unknown) => void) => void;

function exchange<Output>({ url, host, method }: HttpRequest, connector: SocketConnector, { timeoutMs, signal }: Deadline, read: ResponseReader<Output>): Promise<Output> {
    return new Promise((resolve, reject) => {
        const socket = url.protocol === "https:" ? openTlsSocket(connector, host) : openPlainSocket(connector, host);
        const request = createRequest({
            method,
            path: `${url.pathname}${url.search}`,
            setHost: false,
            maxHeaderSize,
            headers: {
                "Host": url.hostname,
                "User-Agent": site.userAgent,
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "identity",
                "Connection": "close"
            },
            createConnection: () => socket
        });
        let settled = false;
        const settle = (outcome: () => void) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            signal.removeEventListener("abort", onAbort);
            request.destroy();
            socket.destroy();
            outcome();
        };
        const fail = (error: unknown) => settle(() => reject(toNetworkError(error)));
        const onAbort = () => fail(new NetworkError("aborted"));
        const timer = setTimeout(() => fail(new NetworkError("timeout")), timeoutMs);

        request.on("response", (response) => {
            const status = response.statusCode ?? 0;
            if (status < 100 || status > 599) fail(new NetworkError("invalid-response"));
            else read(response, (output) => settle(() => resolve(output)), fail);
        });
        request.on("error", fail);
        if (signal.aborted) onAbort();
        else signal.addEventListener("abort", onAbort, { once: true });
        request.end();
    });
}

export function sendRequest(request: HttpRequest, connector: SocketConnector, deadline: Deadline): Promise<HttpProbe> {
    return exchange(request, connector, deadline, (response, finish) => {
        finish({ status: response.statusCode ?? 0, method: request.method, headers: toHeaderMap(response.rawHeaders) });
    });
}

function isReadableDocument({ statusCode = 0, headers }: IncomingMessage): boolean {
    const encoding = headers["content-encoding"]?.trim().toLowerCase();
    return statusCode >= 200 && statusCode < 300
        && (headers["content-type"] ?? "").toLowerCase().includes("text/html")
        && (!encoding || encoding === "identity");
}

export function readDocumentHead(url: URL, host: PinnedHost, connector: SocketConnector, deadline: Deadline): Promise<string | null> {
    return exchange({ url, host, method: "GET" }, connector, deadline, (response, finish, fail) => {
        if (!isReadableDocument(response)) {
            finish(null);
            return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        const complete = () => finish(Buffer.concat(chunks).toString("utf8"));
        response.on("data", (chunk: Buffer) => {
            chunks.push(chunk);
            size += chunk.length;
            if (size >= maxDocumentHeadBytes || Buffer.concat(chunks).toString("latin1").toLowerCase().includes("</head>")) complete();
        });
        response.on("end", complete);
        response.on("error", fail);
    });
}
