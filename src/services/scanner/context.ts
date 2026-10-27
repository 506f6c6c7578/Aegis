import type { HttpProbe } from "@/domain/audit/model";
import type { SocketConnector } from "@/lib/network/connector";
import { NetworkError } from "@/lib/network/errors";
import { type AddressResolver, type PinnedHost, resolvePinnedHost } from "@/lib/network/resolve";
import type { Deadline } from "@/lib/network/socket";
import { sendRequest } from "@/services/scanner/http-client";

const getFallbackStatuses = new Set([400, 403, 405, 501]);

export interface ScanContext {
    connector: SocketConnector;
    deadline: Deadline;
    pinHost: (hostname: string) => Promise<PinnedHost>;
}

export function createHostPinner(resolver: AddressResolver): ScanContext["pinHost"] {
    const pinned = new Map<string, Promise<PinnedHost>>();
    return (hostname) => {
        const existing = pinned.get(hostname);
        if (existing) return existing;
        const host = resolvePinnedHost(hostname, resolver);
        pinned.set(hostname, host);
        return host;
    };
}

export function isAbort(error: unknown): boolean {
    return error instanceof NetworkError && error.code === "aborted";
}

export async function probe(url: URL, { connector, deadline, pinHost }: ScanContext): Promise<HttpProbe> {
    const host = await pinHost(url.hostname);
    const head = await sendRequest({ url, host, method: "HEAD" }, connector, deadline).catch((error: unknown) => {
        if (isAbort(error) || (error instanceof NetworkError && error.code === "timeout")) throw error;
        return null;
    });
    if (head && !getFallbackStatuses.has(head.status)) return head;
    return sendRequest({ url, host, method: "GET" }, connector, deadline);
}
