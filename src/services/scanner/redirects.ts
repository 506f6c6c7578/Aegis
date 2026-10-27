import { maxRedirects } from "@/domain/audit/limits";
import type { HttpEntry, HttpProbe, RedirectChain, RedirectHop, RedirectOutcome } from "@/domain/audit/model";
import { formatDisplayUrl } from "@/lib/network/display";
import { NetworkError } from "@/lib/network/errors";
import { evaluateRedirect } from "@/lib/network/redirect-policy";
import { isAbort, probe, type ScanContext } from "@/services/scanner/context";

const redirectStatuses = new Set([301, 302, 303, 307, 308]);

export interface ChainResult {
    chain: RedirectChain;
    final: (HttpProbe & { url: string }) | null;
    finalUrl: URL | null;
}

function readLocation({ status, headers }: HttpProbe): string | null {
    return redirectStatuses.has(status) ? headers.get("location")?.[0] ?? null : null;
}

export async function followRedirects(start: URL, scope: string, context: ScanContext): Promise<ChainResult> {
    const hops: RedirectHop[] = [];
    const visited = new Set<string>();
    let final: ChainResult["final"] = null;
    let finalUrl: URL | null = null;
    let current = start;

    const finish = (outcome: RedirectOutcome, destination: URL | null = null): ChainResult => ({
        chain: { hops, outcome, refusedDestination: destination ? formatDisplayUrl(destination) : null },
        final,
        finalUrl
    });

    for (let step = 0; step <= maxRedirects; step += 1) {
        visited.add(current.href);
        let response: HttpProbe;
        try {
            response = await probe(current, context);
        } catch (error) {
            if (step === 0 || isAbort(error)) throw error;
            const refused = error instanceof NetworkError && (error.code === "forbidden-address" || error.code === "dns-not-found");
            return refused ? finish("invalid-host", current) : finish("request-failed");
        }
        final = { ...response, url: formatDisplayUrl(current) };
        finalUrl = current;
        const hop: RedirectHop = { url: final.url, status: response.status, method: response.method, location: null };
        hops.push(hop);

        if (!redirectStatuses.has(response.status)) return finish("completed");
        const location = readLocation(response);
        if (!location) return finish("missing-location");

        const decision = evaluateRedirect(location, current, scope);
        const destination = decision.allowed ? decision.url : decision.destination;
        hop.location = destination ? formatDisplayUrl(destination) : null;
        if (!decision.allowed) return finish(decision.reason, decision.destination);
        if (decision.url.protocol === "http:") return finish("insecure-redirect", decision.url);
        if (visited.has(decision.url.href)) return finish("loop", decision.url);
        current = decision.url;
    }
    return finish("too-many-redirects");
}

export async function probeHttpEntry(domain: string, context: ScanContext): Promise<HttpEntry> {
    const url = new URL(`http://${domain}/`);
    let response: HttpProbe;
    try {
        response = await probe(url, context);
    } catch (error) {
        if (isAbort(error)) throw error;
        return { available: false };
    }
    const location = readLocation(response);
    if (!location) return { available: true, status: response.status, target: "none", location: null };

    const decision = evaluateRedirect(location, url, domain);
    const destination = decision.allowed ? decision.url : decision.destination;
    const display = destination ? formatDisplayUrl(destination) : null;
    if (destination?.protocol === "https:" && (decision.allowed || decision.reason === "out-of-scope")) {
        return { available: true, status: response.status, target: destination.hostname === domain ? "https-same-host" : "https-other-host", location: display };
    }
    return { available: true, status: response.status, target: decision.allowed ? "http" : "refused", location: display };
}
