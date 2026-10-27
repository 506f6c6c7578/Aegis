import { NetworkError } from "@/lib/network/errors";
import { isPublicAddress } from "@/lib/network/address-policy";

declare const publicAddressBrand: unique symbol;

export type PublicAddress = string & { readonly [publicAddressBrand]: true };

export interface PinnedHost {
    hostname: string;
    address: PublicAddress;
    family: 4 | 6;
}

export interface AddressResolver {
    resolve4: (hostname: string) => Promise<readonly string[]>;
    resolve6: (hostname: string) => Promise<readonly string[]>;
}

export function assertPublicAddress(address: string): PublicAddress {
    if (!isPublicAddress(address)) throw new NetworkError("forbidden-address");
    return address as PublicAddress;
}

export async function resolvePinnedHost(hostname: string, resolver: AddressResolver): Promise<PinnedHost> {
    const [ipv4, ipv6] = await Promise.all([resolver.resolve4(hostname), resolver.resolve6(hostname)]);
    const addresses = [...ipv4, ...ipv6];
    if (addresses.length === 0) throw new NetworkError("dns-not-found");
    if (!addresses.every(isPublicAddress)) throw new NetworkError("forbidden-address");
    const [ipv4Address] = ipv4;
    const [ipv6Address = ""] = ipv6;
    return ipv4Address
        ? { hostname, address: assertPublicAddress(ipv4Address), family: 4 }
        : { hostname, address: assertPublicAddress(ipv6Address), family: 6 };
}
