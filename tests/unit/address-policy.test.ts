import { describe, expect, it } from "vitest";
import { forbiddenIpv4Ranges, forbiddenIpv6Ranges, isPublicAddress } from "@/lib/network/address-policy";

function lastIpv4Address(network: string, prefix: number): string {
    const value = network.split(".").reduce((total, octet) => total * 256 + Number(octet), 0);
    const last = value + 2 ** (32 - prefix) - 1;
    return [24, 16, 8, 0].map((shift) => Math.floor(last / 2 ** shift) % 256).join(".");
}

describe("isPublicAddress : plages IPv4 interdites", () => {
    it.each(forbiddenIpv4Ranges.map(({ network, prefix, label }) => [`${network}/${prefix}`, label, network, prefix] as const))(
        "refuse %s (%s), première et dernière adresse",
        (_, __, network, prefix) => {
            expect(isPublicAddress(network)).toBe(false);
            expect(isPublicAddress(lastIpv4Address(network, prefix))).toBe(false);
        }
    );

    it.each([
        ["127.0.0.1", "boucle locale"],
        ["10.1.2.3", "réseau privé"],
        ["172.16.0.1", "réseau privé"],
        ["172.31.255.254", "réseau privé"],
        ["192.168.1.1", "réseau privé"],
        ["169.254.169.254", "métadonnées cloud"],
        ["100.64.0.1", "CGNAT"],
        ["100.100.100.200", "métadonnées Alibaba Cloud"],
        ["0.0.0.0", "adresse non spécifiée"],
        ["224.0.0.1", "multidiffusion"],
        ["239.255.255.250", "multidiffusion"],
        ["255.255.255.255", "diffusion"],
        ["240.0.0.1", "réservé"],
        ["192.0.2.10", "documentation"],
        ["198.51.100.10", "documentation"],
        ["203.0.113.10", "documentation"],
        ["198.18.0.1", "tests de performance"],
        ["192.0.0.170", "IETF"]
    ])("refuse %s (%s)", (address) => {
        expect(isPublicAddress(address)).toBe(false);
    });

    it.each(["8.8.8.8", "1.1.1.1", "9.9.9.9", "93.184.215.14", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1", "11.0.0.1", "223.255.255.254"])(
        "accepte l'adresse publique %s",
        (address) => {
            expect(isPublicAddress(address)).toBe(true);
        }
    );
});

describe("isPublicAddress : plages IPv6 interdites", () => {
    it.each(forbiddenIpv6Ranges.map(({ network, prefix }) => `${network}/${prefix}`))("refuse le réseau %s", (range) => {
        const [network = ""] = range.split("/");
        expect(isPublicAddress(network.endsWith("::") ? `${network}1` : network)).toBe(false);
    });

    it.each([
        ["::", "non spécifiée"],
        ["::1", "boucle locale"],
        ["0:0:0:0:0:0:0:1", "boucle locale développée"],
        ["fe80::1", "lien local"],
        ["febf:ffff::1", "lien local"],
        ["fec0::1", "site local obsolète"],
        ["fc00::1", "adresse unique locale"],
        ["fd12:3456:789a::1", "adresse unique locale"],
        ["fd00:ec2::254", "métadonnées AWS"],
        ["ff02::1", "multidiffusion"],
        ["ff05::2", "multidiffusion"],
        ["100::1", "suppression"],
        ["64:ff9b::a00:1", "traduction NAT64"],
        ["64:ff9b:1::1", "traduction NAT64 locale"],
        ["2001:db8::1", "documentation"],
        ["3fff::1", "documentation"],
        ["2001::1", "Teredo"],
        ["2002:a00:1::1", "6to4 vers un réseau privé"],
        ["fe80::1%eth0", "identifiant de zone"],
        ["4000::1", "hors unicast global"]
    ])("refuse %s (%s)", (address) => {
        expect(isPublicAddress(address)).toBe(false);
    });

    it.each([
        ["::ffff:127.0.0.1", "boucle locale"],
        ["::ffff:10.0.0.1", "réseau privé"],
        ["::ffff:169.254.169.254", "métadonnées cloud"],
        ["::ffff:7f00:1", "boucle locale en hexadécimal"],
        ["::ffff:a9fe:a9fe", "métadonnées en hexadécimal"],
        ["::127.0.0.1", "IPv4 compatible obsolète"],
        ["::ffff:8.8.8.8", "adresse publique encapsulée, refusée par prudence"]
    ])("refuse l'adresse IPv4-mapped %s (%s)", (address) => {
        expect(isPublicAddress(address)).toBe(false);
    });

    it.each(["2606:4700:4700::1111", "2620:fe::fe", "2a00:1450:4007:80e::200e", "2001:4860:4860::8888"])("accepte l'adresse publique %s", (address) => {
        expect(isPublicAddress(address)).toBe(true);
    });
});

describe("isPublicAddress : formes ambiguës", () => {
    it.each(["010.0.0.1", "0x7f.0.0.1", "127.1", "2130706433", "localhost", "", " 8.8.8.8", "8.8.8.8 ", "[2606:4700::1]", "1.1.1.1.1"])(
        "refuse %j",
        (address) => {
            expect(isPublicAddress(address)).toBe(false);
        }
    );
});
