import { ArrowDown, CornerDownRight } from "lucide-react";
import { CheckList } from "@/components/audit/CheckCard";
import { FactList, ReportSection } from "@/components/audit/ReportSection";
import { Badge } from "@/components/ui/badge";
import type { AuditReport, HttpEntryTarget, RedirectOutcome } from "@/domain/audit/model";
import { maxRedirects } from "@/domain/audit/limits";

const outcomeLabels: Record<RedirectOutcome, string> = {
    "completed": "La chaîne aboutit à une réponse finale.",
    "too-many-redirects": `Arrêt après ${maxRedirects} redirections.`,
    "loop": "Arrêt : la chaîne revient sur une adresse déjà visitée.",
    "insecure-redirect": "Arrêt : redirection vers une adresse HTTP non chiffrée.",
    "missing-location": "Arrêt : redirection sans en-tête Location.",
    "request-failed": "Arrêt : une destination n'a pas répondu.",
    "invalid-location": "Arrêt : destination invalide.",
    "unsupported-scheme": "Arrêt : protocole non pris en charge.",
    "credentials": "Arrêt : identifiants présents dans l'URL.",
    "port": "Arrêt : port non standard.",
    "ip-literal": "Arrêt : redirection vers une adresse IP brute.",
    "invalid-host": "Arrêt : nom d'hôte invalide ou non public.",
    "out-of-scope": "Arrêt : la destination sort du domaine vérifié et n'est pas contactée."
};

const entryLabels: Record<HttpEntryTarget, string> = {
    "https-same-host": "Redirige vers HTTPS sur le même nom d'hôte",
    "https-other-host": "Redirige vers HTTPS sur un autre nom d'hôte",
    "http": "Redirige vers une autre adresse HTTP",
    "refused": "Redirige vers une destination non conforme",
    "none": "Répond sans rediriger"
};

export function RedirectChain({ report }: { report: AuditReport }) {
    const { hops, outcome, refusedDestination } = report.redirects;
    const { httpEntry } = report;
    return (
        <ReportSection id="redirections" title="Redirections"
                       description={`Aegis part de https://${report.domain}/ et suit au plus ${maxRedirects} redirections, uniquement en HTTPS et dans le domaine vérifié.`}>
            {hops.length > 0 && (
                <ol className="grid gap-2" aria-label="Chaîne de redirections">
                    {hops.map(({ url, status, method }, index) => (
                        <li key={`${url}-${index}`} className="grid gap-2">
                            {index > 0 && <ArrowDown className="ml-4 size-4 text-muted-foreground" aria-hidden="true"/>}
                            <div className="flex flex-wrap items-center gap-2 rounded-xl border px-4 py-3">
                                <Badge variant="outline" className="tabular-nums">{status}</Badge>
                                <span className="text-xs text-muted-foreground">{method}</span>
                                <code className="font-mono text-xs break-all text-foreground">{url}</code>
                            </div>
                        </li>
                    ))}
                </ol>
            )}
            <p className="flex items-start gap-2 text-sm">
                <CornerDownRight className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true"/>
                <span>
                    {outcomeLabels[outcome]}
                    {refusedDestination && <> Destination : <code className="font-mono text-xs break-all">{refusedDestination}</code></>}
                </span>
            </p>
            <FactList facts={[
                {
                    label: `http://${report.domain}/`,
                    value: httpEntry.available
                        ? `HTTP ${httpEntry.status} · ${entryLabels[httpEntry.target]}${httpEntry.location ? ` (${httpEntry.location})` : ""}`
                        : "Port 80 fermé ou injoignable"
                }
            ]}/>
            <CheckList label="Contrôles des redirections" checks={report.checks.filter(({ id }) => id === "redirect-chain")}/>
        </ReportSection>
    );
}
