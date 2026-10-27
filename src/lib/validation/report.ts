import * as z from "zod/mini";
import {
    type AuditCheck,
    type AuditReport,
    categoryIds,
    checkStatuses,
    type CookieView,
    type CspPolicyView,
    httpEntryTargets,
    priorities,
    redirectOutcomes,
    tlsFailureReasons,
    type TlsObservation
} from "@/domain/audit/model";

const text = z.string().check(z.maxLength(4_096));
const nullableText = z.nullable(text);
const timestamp = z.number();
const count = z.int().check(z.gte(0));
const method = z.enum(["HEAD", "GET"]);
const status = z.int().check(z.gte(100), z.lte(599));

const checkSchema: z.ZodMiniType<AuditCheck> = z.object({
    id: text,
    category: z.enum(categoryIds),
    status: z.enum(checkStatuses),
    priority: z.enum(priorities),
    title: text,
    explanation: text,
    recommendation: nullableText,
    observed: nullableText,
    reference: z.nullable(z.object({ label: text, url: z.url({ protocol: /^https$/ }) }))
});

const certificateSummarySchema = z.object({ subject: text, issuer: text, validFrom: timestamp, validTo: timestamp });

const tlsSchema: z.ZodMiniType<TlsObservation> = z.union([
    z.object({
        status: z.literal("established"),
        protocol: text,
        cipher: text,
        certificate: z.extend(certificateSummarySchema, {
            subjectAltNames: z.array(text).check(z.maxLength(20)),
            key: nullableText,
            fingerprint: text
        }),
        chain: z.array(certificateSummarySchema).check(z.maxLength(4))
    }),
    z.object({ status: z.literal("failed"), reason: z.enum(tlsFailureReasons) })
]);

const cookieSchema: z.ZodMiniType<CookieView> = z.object({
    name: text,
    secure: z.boolean(),
    httpOnly: z.boolean(),
    sameSite: z.nullable(z.enum(["Strict", "Lax", "None"])),
    domain: nullableText,
    path: nullableText,
    lifetime: z.union([
        z.object({ kind: z.literal("session") }),
        z.object({ kind: z.literal("persistent"), seconds: count })
    ]),
    sensitive: z.boolean(),
    prefix: z.nullable(z.enum(["__Host-", "__Secure-"]))
});

const cspSchema: z.ZodMiniType<CspPolicyView> = z.object({
    mode: z.enum(["enforce", "report-only"]),
    source: z.enum(["header", "meta"]),
    directives: z.array(z.object({ name: text, sources: z.array(text).check(z.maxLength(40)) })).check(z.maxLength(40))
});

export const reportSchema: z.ZodMiniType<AuditReport> = z.object({
    version: z.literal(1),
    id: text,
    domain: text,
    displayDomain: text,
    startedAt: timestamp,
    durationMs: count,
    expiresAt: timestamp,
    score: z.object({
        value: z.int().check(z.gte(0), z.lte(100)),
        categories: z.array(z.object({ id: z.enum(categoryIds), weight: z.number(), earned: z.number(), evaluated: z.boolean() }))
    }),
    summary: z.object({ pass: count, warning: count, fail: count, notApplicable: count }),
    checks: z.array(checkSchema).check(z.maxLength(60)),
    tls: tlsSchema,
    redirects: z.object({
        hops: z.array(z.object({ url: text, status, method, location: nullableText })).check(z.maxLength(6)),
        outcome: z.enum(redirectOutcomes),
        refusedDestination: nullableText
    }),
    httpEntry: z.union([
        z.object({ available: z.literal(false) }),
        z.object({ available: z.literal(true), status, target: z.enum(httpEntryTargets), location: nullableText })
    ]),
    response: z.nullable(z.object({ url: text, status, method })),
    headers: z.array(z.object({ name: text, value: nullableText, checkId: nullableText })).check(z.maxLength(30)),
    csp: z.array(cspSchema).check(z.maxLength(4)),
    cookies: z.array(cookieSchema).check(z.maxLength(50))
});
