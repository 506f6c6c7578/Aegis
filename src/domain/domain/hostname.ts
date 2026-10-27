import { isIP } from "node:net";
import { domainToASCII, domainToUnicode } from "node:url";
import { parse } from "tldts";
import { detectHostnameShapeError, type HostnameError, hostnameLimits } from "@/domain/domain/input";

export interface NormalizedHostname {
    ascii: string;
    unicode: string;
}

export type HostnameResult = { ok: true; hostname: NormalizedHostname } | { ok: false; error: HostnameError };

const labelPattern = new RegExp(`^(?!-)[a-z0-9-]{1,${hostnameLimits.labelMaxLength}}(?<!-)$`);
const reservedHyphenPattern = /^(?!xn)..--/;
const reservedTopLevelDomains = new Set(["arpa", "localhost", "local", "internal", "localdomain", "lan", "home", "corp", "intranet", "private"]);

function failure(error: HostnameError): HostnameResult {
    return { ok: false, error };
}

function findLabelError(ascii: string): HostnameError | null {
    const labels = ascii.split(".");
    if (labels.length < 2) return "single-label";
    const invalid = labels.some((label) => !labelPattern.test(label) || reservedHyphenPattern.test(label));
    if (invalid || /^\d+$/.test(labels.at(-1) ?? "")) return "invalid-label";
    return reservedTopLevelDomains.has(labels.at(-1) ?? "") ? "special-use" : null;
}

export function normalizeHostname(input: string): HostnameResult {
    const trimmed = input.trim();
    const shapeError = detectHostnameShapeError(trimmed);
    if (shapeError) return failure(shapeError);

    const ascii = domainToASCII(trimmed.replace(/\.$/, "").normalize("NFC"));
    if (!ascii) return failure("invalid-label");
    if (isIP(ascii)) return failure("ip-address");
    if (ascii.length > hostnameLimits.asciiMaxLength) return failure("too-long");

    const labelError = findLabelError(ascii);
    if (labelError) return failure(labelError);

    const parsed = parse(ascii, { extractHostname: false, allowPrivateDomains: false, detectSpecialUse: true });
    if (parsed.isIp) return failure("ip-address");
    if (parsed.isSpecialUse) return failure("special-use");
    if (!parsed.isIcann) return failure("not-public");
    if (!parsed.domain) return failure("public-suffix");

    return { ok: true, hostname: { ascii, unicode: domainToUnicode(ascii) } };
}
