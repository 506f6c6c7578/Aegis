import { BlockList, isIP } from "node:net";

type AddressFamily = "ipv4" | "ipv6";

interface AddressRange {
    network: string;
    prefix: number;
    label: string;
}

export const forbiddenIpv4Ranges: readonly AddressRange[] = [
    { network: "0.0.0.0", prefix: 8, label: "Réseau courant" },
    { network: "10.0.0.0", prefix: 8, label: "Réseau privé" },
    { network: "100.64.0.0", prefix: 10, label: "CGNAT" },
    { network: "127.0.0.0", prefix: 8, label: "Boucle locale" },
    { network: "169.254.0.0", prefix: 16, label: "Lien local et métadonnées cloud" },
    { network: "172.16.0.0", prefix: 12, label: "Réseau privé" },
    { network: "192.0.0.0", prefix: 24, label: "Affectations de protocoles IETF" },
    { network: "192.0.2.0", prefix: 24, label: "Documentation" },
    { network: "192.31.196.0", prefix: 24, label: "AS112" },
    { network: "192.52.193.0", prefix: 24, label: "AMT" },
    { network: "192.88.99.0", prefix: 24, label: "Relais 6to4" },
    { network: "192.168.0.0", prefix: 16, label: "Réseau privé" },
    { network: "192.175.48.0", prefix: 24, label: "AS112" },
    { network: "198.18.0.0", prefix: 15, label: "Tests de performance" },
    { network: "198.51.100.0", prefix: 24, label: "Documentation" },
    { network: "203.0.113.0", prefix: 24, label: "Documentation" },
    { network: "224.0.0.0", prefix: 4, label: "Multidiffusion" },
    { network: "240.0.0.0", prefix: 4, label: "Réservé et diffusion" }
];

export const globalUnicastIpv6Range: AddressRange = { network: "2000::", prefix: 3, label: "Unicast global" };

export const forbiddenIpv6Ranges: readonly AddressRange[] = [
    { network: "2001::", prefix: 23, label: "Affectations de protocoles IETF" },
    { network: "2001:db8::", prefix: 32, label: "Documentation" },
    { network: "2002::", prefix: 16, label: "6to4" },
    { network: "2620:4f:8000::", prefix: 48, label: "AS112" },
    { network: "3fff::", prefix: 20, label: "Documentation" }
];

function createBlockList(ranges: readonly AddressRange[], family: AddressFamily): BlockList {
    const blockList = new BlockList();
    for (const { network, prefix } of ranges) blockList.addSubnet(network, prefix, family);
    return blockList;
}

const forbiddenIpv4 = createBlockList(forbiddenIpv4Ranges, "ipv4");
const globalUnicastIpv6 = createBlockList([globalUnicastIpv6Range], "ipv6");
const forbiddenIpv6 = createBlockList(forbiddenIpv6Ranges, "ipv6");

function isPublicIpv6(address: string): boolean {
    if (address.includes("%") || address.includes(".")) return false;
    return globalUnicastIpv6.check(address, "ipv6") && !forbiddenIpv6.check(address, "ipv6");
}

function classify(address: string): boolean {
    switch (isIP(address)) {
        case 4:
            return !forbiddenIpv4.check(address, "ipv4");
        case 6:
            return isPublicIpv6(address);
        default:
            return false;
    }
}

export function isPublicAddress(address: string): boolean {
    try {
        return classify(address);
    } catch {
        return false;
    }
}
