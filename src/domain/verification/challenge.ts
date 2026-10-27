import { safeEqual, sha256 } from "@/lib/crypto/hash";

const maxRecordsInspected = 20;
const maxRecordLength = 512;

export interface ChallengeBinding {
    challengeId: string;
    domain: string;
}

export function hashChallengeToken({ challengeId, domain }: ChallengeBinding, token: string): string {
    return sha256(`aegis:challenge:v1:${challengeId}:${domain}:${token}`);
}

function normalizeRecordValue(chunks: readonly string[]): string | null {
    const value = chunks.join("").trim().replace(/^"(.*)"$/, "$1");
    return value.length > 0 && value.length <= maxRecordLength ? value : null;
}

export function matchesChallenge(records: readonly (readonly string[])[], binding: ChallengeBinding, expectedHash: string): boolean {
    return records
        .slice(0, maxRecordsInspected)
        .map(normalizeRecordValue)
        .some((value) => value !== null && safeEqual(hashChallengeToken(binding, value), expectedHash));
}
