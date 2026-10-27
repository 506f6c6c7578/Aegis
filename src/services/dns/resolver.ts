import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import { NetworkError, readErrorCode } from "@/lib/network/errors";
import type { AddressResolver } from "@/lib/network/resolve";

const queryTimeoutMs = 3_000;
const queryTries = 2;
const emptyAnswerCodes = new Set(["ENOTFOUND", "ENODATA", "NOTFOUND", "NODATA"]);
const serverPattern = /^(?:\[(?<ipv6>[0-9a-f:]+)\]|(?<ipv4>[\d.]+))(?::(?<port>\d{1,5}))?$/i;

export interface ControlledResolver extends AddressResolver {
    resolveTxt: (hostname: string) => Promise<readonly (readonly string[])[]>;
}

export function parseDnsServers(value: string): string[] {
    const servers = value.split(",").map((server) => server.trim()).filter(Boolean);
    const valid = servers.every((server) => {
        const groups = serverPattern.exec(server)?.groups;
        const address = groups?.ipv6 ?? groups?.ipv4 ?? "";
        const port = Number(groups?.port ?? 53);
        return isIP(address) !== 0 && port > 0 && port < 65_536;
    });
    if (servers.length === 0 || !valid) throw new Error("AEGIS_DNS_SERVERS doit lister des adresses IP de résolveurs.");
    return servers;
}

async function query<Answer>(lookup: () => Promise<Answer[]>): Promise<Answer[]> {
    try {
        return await lookup();
    } catch (error) {
        if (emptyAnswerCodes.has(readErrorCode(error) ?? "")) return [];
        throw new NetworkError("dns-failure");
    }
}

export function createControlledResolver(servers: readonly string[]): ControlledResolver {
    const resolver = new Resolver({ timeout: queryTimeoutMs, tries: queryTries });
    resolver.setServers(servers);
    return {
        resolve4: (hostname) => query(() => resolver.resolve4(hostname)),
        resolve6: (hostname) => query(() => resolver.resolve6(hostname)),
        resolveTxt: (hostname) => query(() => resolver.resolveTxt(hostname))
    };
}
