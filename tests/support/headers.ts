import type { HeaderMap } from "@/domain/audit/model";

export function headerMap(headers: Record<string, string | readonly string[]>): HeaderMap {
    return new Map(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), typeof value === "string" ? [value] : [...value]]));
}
