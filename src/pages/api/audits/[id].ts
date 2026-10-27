import type { APIRoute } from "astro";
import { cookieNames, readCookie } from "@/lib/http/cookies";
import { errorResponse, jsonResponse, methodNotAllowed } from "@/lib/http/responses";
import { reportIdSchema } from "@/lib/validation/api";
import { audits, verification } from "@/services/runtime";

export const prerender = false;

export const GET: APIRoute = ({ params, cookies }) => {
    const id = reportIdSchema.safeParse(params.id);
    const session = verification.readSession(readCookie(cookies, cookieNames.session));
    const report = id.success && session ? audits.getReport({ session, id: id.data }) : null;
    return report ? jsonResponse({ report }) : errorResponse(404, "Rapport introuvable ou expiré.");
};

export const ALL = methodNotAllowed("GET");
