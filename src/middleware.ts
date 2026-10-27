import { defineMiddleware } from "astro:middleware";
import { reportPathPrefix } from "@/data/site";
import { securityHeaders } from "@/lib/http/security-headers";

const privatePathPrefixes = ["/api/", reportPathPrefix];
const policyHeader = "Content-Security-Policy";

export const onRequest = defineMiddleware(async ({ url }, next) => {
    const response = await next();
    for (const [name, value] of Object.entries(securityHeaders)) {
        if (name === policyHeader) response.headers.append(name, value);
        else response.headers.set(name, value);
    }
    if (privatePathPrefixes.some((prefix) => url.pathname.startsWith(prefix))) response.headers.set("Cache-Control", "no-store");
    return response;
});
