import { extractMetaPolicies } from "@/domain/audit/csp";
import type { ScanObservations } from "@/domain/audit/model";
import { isAbort, type ScanContext } from "@/services/scanner/context";
import { readDocumentHead } from "@/services/scanner/http-client";
import { type ChainResult, followRedirects, probeHttpEntry } from "@/services/scanner/redirects";
import { inspectTls } from "@/services/tls/inspect";

async function readMetaPolicies({ final, finalUrl }: ChainResult, context: ScanContext): Promise<string[]> {
    if (!final || !finalUrl || final.status < 200 || final.status >= 300) return [];
    if (!final.headers.get("content-type")?.some((value) => value.toLowerCase().includes("text/html"))) return [];
    try {
        const host = await context.pinHost(finalUrl.hostname);
        const document = await readDocumentHead(finalUrl, host, context.connector, context.deadline);
        return document ? extractMetaPolicies(document) : [];
    } catch (error) {
        if (isAbort(error)) throw error;
        return [];
    }
}

export async function runScan(domain: string, context: ScanContext): Promise<ScanObservations> {
    const host = await context.pinHost(domain);
    const [tls, chain, httpEntry] = await Promise.all([
        inspectTls(host, context.connector, context.deadline),
        followRedirects(new URL(`https://${domain}/`), domain, context).catch((error: unknown) => {
            if (isAbort(error)) throw error;
            return null;
        }),
        probeHttpEntry(domain, context)
    ]);
    return {
        domain,
        tls,
        chain: chain?.chain ?? { hops: [], outcome: "request-failed", refusedDestination: null },
        final: chain?.final ?? null,
        httpEntry,
        metaPolicies: chain ? await readMetaPolicies(chain, context) : []
    };
}
