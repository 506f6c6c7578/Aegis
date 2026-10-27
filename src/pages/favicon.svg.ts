import type { APIRoute } from "astro";
import { createLogoSvg } from "@/lib/brand";

export const GET: APIRoute = () =>
    new Response(createLogoSvg(64), { headers: { "Content-Type": "image/svg+xml" } });
