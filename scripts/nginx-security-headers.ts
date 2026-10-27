import { securityHeaders } from "../src/lib/http/security-headers.ts";

const lines = Object.entries(securityHeaders).flatMap(([name, value]) => [
    `proxy_hide_header ${name};`,
    `add_header ${name} "${value}" always;`
]);

process.stdout.write(`${lines.join("\n")}\n`);
