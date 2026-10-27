import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { normalizeHostname } from "@/domain/domain/hostname";
import type { NormalizedHostname } from "@/domain/domain/hostname";
import { verificationPolicy } from "@/domain/verification/policy";
import type { SessionToken } from "@/domain/verification/tokens";
import { createTokenSigner } from "@/lib/crypto/signed-token";
import { NetworkError } from "@/lib/network/errors";
import { auditPolicy, createAuditService } from "@/services/audits/service";
import { createVerificationService, type VerificationService } from "@/services/verification/service";
import { createFakeResolver, publicAddress, startTarget, type Target, testDomain } from "../support/target";

const signer = createTokenSigner("secret-de-test-suffisamment-long-pour-hkdf-0123456789");

function hostname(input: string): NormalizedHostname {
    const result = normalizeHostname(input);
    if (!result.ok) throw new Error(result.error);
    return result.hostname;
}

function createClock() {
    let time = Date.UTC(2026, 9, 27, 9);
    return { now: () => time, advance: (milliseconds: number) => { time += milliseconds; } };
}

interface Harness {
    clock: ReturnType<typeof createClock>;
    txt: Map<string, string[][] | Error>;
    verification: VerificationService;
}

function createHarness(): Harness {
    const clock = createClock();
    const txt = new Map<string, string[][] | Error>();
    const verification = createVerificationService({
        signer,
        now: clock.now,
        resolver: {
            resolveTxt: async (name) => {
                const records = txt.get(name) ?? [];
                if (records instanceof Error) throw records;
                return records;
            }
        }
    });
    return { clock, txt, verification };
}

function issue({ verification }: Harness, session: SessionToken, domain = testDomain) {
    const result = verification.issueChallenge({ session, hostname: hostname(domain), client: "203.0.113.1" });
    if (!result.ok) throw new Error(result.error);
    return result;
}

describe("vérification de propriété", () => {
    let harness: Harness;
    let session: SessionToken;

    beforeEach(() => {
        harness = createHarness();
        session = harness.verification.openSession(undefined).payload;
    });

    const confirm = (challengeToken: string | undefined, currentSession = session) =>
        harness.verification.confirmChallenge({ session: currentSession, challengeToken, client: "203.0.113.1" });

    it("délivre une preuve liée au domaine exact et à la session après publication du TXT", async () => {
        const { challenge, challengeToken } = issue(harness, session);
        expect(challenge.recordName).toBe(`_aegis-verify.${testDomain}`);
        expect(challengeToken).not.toContain(challenge.recordValue);
        expect(Buffer.from(challengeToken.split(".")[0] ?? "", "base64url").toString()).not.toContain(challenge.recordValue);

        harness.txt.set(challenge.recordName, [["autre-valeur"], [challenge.recordValue]]);
        const result = await confirm(challengeToken);
        expect(result).toMatchObject({ ok: true, status: "verified", domain: testDomain });
        if (!result.ok || result.status !== "verified") return;

        expect(harness.verification.readProof({ session, proofToken: result.proofToken, domain: testDomain })).not.toBeNull();
        expect(harness.verification.readProof({ session, proofToken: result.proofToken, domain: `www.${testDomain}` })).toBeNull();
        const otherSession = harness.verification.openSession(undefined).payload;
        expect(harness.verification.readProof({ session: otherSession, proofToken: result.proofToken, domain: testDomain })).toBeNull();

        harness.clock.advance(verificationPolicy.proofTtlMs);
        expect(harness.verification.readProof({ session, proofToken: result.proofToken, domain: testDomain })).toBeNull();
    });

    it("gère la propagation DNS, une valeur erronée et un résolveur indisponible", async () => {
        const { challenge, challengeToken } = issue(harness, session);
        await expect(confirm(challengeToken)).resolves.toMatchObject({ status: "pending", reason: "not-found", attemptsRemaining: 9 });

        harness.clock.advance(verificationPolicy.confirmCooldownMs);
        harness.txt.set(challenge.recordName, [["mauvaise-valeur"]]);
        await expect(confirm(challengeToken)).resolves.toMatchObject({ status: "pending", reason: "mismatch" });

        harness.clock.advance(verificationPolicy.confirmCooldownMs);
        harness.txt.set(challenge.recordName, new NetworkError("dns-failure"));
        await expect(confirm(challengeToken)).resolves.toMatchObject({ status: "pending", reason: "dns-error" });
    });

    it("n'interroge que le TXT du domaine exact", async () => {
        const { challenge, challengeToken } = issue(harness, session);
        harness.txt.set(`_aegis-verify.www.${testDomain}`, [[challenge.recordValue]]);
        harness.txt.set(testDomain, [[challenge.recordValue]]);
        await expect(confirm(challengeToken)).resolves.toMatchObject({ status: "pending", reason: "not-found" });
    });

    it("impose un délai entre deux vérifications et limite les tentatives", async () => {
        const { challengeToken } = issue(harness, session);
        await confirm(challengeToken);
        await expect(confirm(challengeToken)).resolves.toMatchObject({ ok: false, error: "rate-limited" });
        for (let attempt = 1; attempt < verificationPolicy.maxConfirmAttempts; attempt += 1) {
            harness.clock.advance(verificationPolicy.confirmCooldownMs);
            await confirm(challengeToken);
        }
        harness.clock.advance(verificationPolicy.confirmCooldownMs);
        await expect(confirm(challengeToken)).resolves.toEqual({ ok: false, error: "attempts-exhausted" });
    });

    it("expire le challenge", async () => {
        const { challenge, challengeToken } = issue(harness, session);
        harness.txt.set(challenge.recordName, [[challenge.recordValue]]);
        harness.clock.advance(verificationPolicy.challengeTtlMs);
        await expect(confirm(challengeToken)).resolves.toEqual({ ok: false, error: "challenge-missing" });
    });

    it("invalide le challenge après succès", async () => {
        const { challenge, challengeToken } = issue(harness, session);
        harness.txt.set(challenge.recordName, [[challenge.recordValue]]);
        await expect(confirm(challengeToken)).resolves.toMatchObject({ status: "verified" });
        await expect(confirm(challengeToken)).resolves.toEqual({ ok: false, error: "challenge-missing" });
    });

    it("refuse un challenge présenté par une autre session ou falsifié", async () => {
        const { challenge, challengeToken } = issue(harness, session);
        harness.txt.set(challenge.recordName, [[challenge.recordValue]]);
        const otherSession = harness.verification.openSession(undefined).payload;
        await expect(confirm(challengeToken, otherSession)).resolves.toEqual({ ok: false, error: "challenge-missing" });
        await expect(confirm(`${challengeToken.slice(0, -2)}aa`)).resolves.toEqual({ ok: false, error: "challenge-missing" });
        await expect(confirm(undefined)).resolves.toEqual({ ok: false, error: "challenge-missing" });
    });

    it("limite la création de challenges", () => {
        for (let index = 0; index < 10; index += 1) issue(harness, session);
        expect(harness.verification.issueChallenge({ session, hostname: hostname(testDomain), client: "203.0.113.1" })).toMatchObject({ ok: false, error: "rate-limited" });
    });

    it("conserve l'identifiant d'une session valide et en crée une nouvelle sinon", () => {
        const opened = harness.verification.openSession(undefined);
        expect(harness.verification.openSession(opened.token).payload.sid).toBe(opened.payload.sid);
        expect(harness.verification.openSession("jeton-invalide").payload.sid).not.toBe(opened.payload.sid);
        expect(harness.verification.readSession("jeton-invalide")).toBeNull();
    });
});

describe("analyse après vérification", () => {
    let target: Target;
    let harness: Harness;

    beforeEach(async () => {
        target = await startTarget();
        harness = createHarness();
    });

    afterEach(() => target.close());

    function createAudits() {
        return createAuditService({
            verification: harness.verification,
            resolver: createFakeResolver({ [testDomain]: [publicAddress] }),
            connector: target.connector,
            now: harness.clock.now
        });
    }

    async function verify(session: SessionToken) {
        const { challenge, challengeToken } = issue(harness, session);
        harness.txt.set(challenge.recordName, [[challenge.recordValue]]);
        const result = await harness.verification.confirmChallenge({ session, challengeToken, client: "203.0.113.1" });
        if (!result.ok || result.status !== "verified") throw new Error("Vérification attendue");
        return result.proofToken;
    }

    it("refuse toute analyse sans preuve valide", async () => {
        const audits = createAudits();
        const session = harness.verification.openSession(undefined).payload;
        const signal = new AbortController().signal;
        await expect(audits.startAudit({ session, proofToken: undefined, domain: testDomain, client: "a", signal })).resolves.toEqual({ ok: false, error: "unauthorized" });
        const proofToken = await verify(session);
        await expect(audits.startAudit({ session, proofToken, domain: `www.${testDomain}`, client: "a", signal })).resolves.toEqual({ ok: false, error: "unauthorized" });
        expect(target.contacted).toEqual([]);
    });

    it("produit un rapport accessible uniquement depuis la session d'origine, puis l'expire", async () => {
        const audits = createAudits();
        const session = harness.verification.openSession(undefined).payload;
        const proofToken = await verify(session);
        const result = await audits.startAudit({ session, proofToken, domain: testDomain, client: "a", signal: new AbortController().signal });
        expect(result.ok).toBe(true);
        if (!result.ok) return;

        expect(result.report.id).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(audits.getReport({ session, id: result.report.id })?.domain).toBe(testDomain);
        expect(audits.getReport({ session: harness.verification.openSession(undefined).payload, id: result.report.id })).toBeNull();
        expect(audits.getReport({ session, id: "A".repeat(43) })).toBeNull();

        harness.clock.advance(auditPolicy.reportTtlMs);
        expect(audits.getReport({ session, id: result.report.id })).toBeNull();
    });

    it("n'autorise qu'une analyse active par session et limite les analyses par domaine", async () => {
        const audits = createAudits();
        const session = harness.verification.openSession(undefined).payload;
        const proofToken = await verify(session);
        const start = () => audits.startAudit({ session, proofToken, domain: testDomain, client: "a", signal: new AbortController().signal });

        const [first, second] = await Promise.all([start(), start()]);
        expect([first.ok, second.ok].sort()).toEqual([false, true]);
        expect([first, second]).toContainEqual({ ok: false, error: "session-busy" });

        for (let index = 0; index < 4; index += 1) await start();
        await expect(start()).resolves.toMatchObject({ ok: false, error: "rate-limited" });
    });

    it("refuse un domaine vérifié qui pointe vers une adresse interne", async () => {
        const audits = createAuditService({
            verification: harness.verification,
            resolver: createFakeResolver({ [testDomain]: ["169.254.169.254"] }),
            connector: target.connector,
            now: harness.clock.now
        });
        const session = harness.verification.openSession(undefined).payload;
        const proofToken = await verify(session);
        await expect(audits.startAudit({ session, proofToken, domain: testDomain, client: "a", signal: new AbortController().signal }))
            .resolves.toEqual({ ok: false, error: "forbidden-address" });
        expect(target.contacted).toEqual([]);
    });
});
