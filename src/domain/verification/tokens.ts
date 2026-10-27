import * as z from "zod/mini";
import { hostnameLimits } from "@/domain/domain/input";
import { randomTokenPattern } from "@/lib/crypto/random";

const identifierSchema = z.string().check(z.regex(randomTokenPattern));
const domainSchema = z.string().check(z.minLength(3), z.maxLength(hostnameLimits.asciiMaxLength));
const expirySchema = z.int().check(z.positive());

export const sessionTokenSchema = z.object({ sid: identifierSchema, exp: expirySchema });
export type SessionToken = z.infer<typeof sessionTokenSchema>;

export const challengeTokenSchema = z.object({
    cid: identifierSchema,
    sid: identifierSchema,
    domain: domainSchema,
    hash: identifierSchema,
    exp: expirySchema
});
export type ChallengeToken = z.infer<typeof challengeTokenSchema>;

export const proofTokenSchema = z.object({ cid: identifierSchema, sid: identifierSchema, domain: domainSchema, exp: expirySchema });
export type ProofToken = z.infer<typeof proofTokenSchema>;
