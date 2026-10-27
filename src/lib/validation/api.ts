import * as z from "zod/mini";
import { hostnameLimits } from "@/domain/domain/input";
import { randomTokenPattern } from "@/lib/crypto/random";

export const domainRequestSchema = z.strictObject({
    domain: z.string().check(z.maxLength(hostnameLimits.inputMaxLength))
});

export const emptyRequestSchema = z.strictObject({});

export const reportIdSchema = z.string().check(z.regex(randomTokenPattern));
