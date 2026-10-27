import { OctagonAlert, TriangleAlert } from "lucide-react";
import { CheckList } from "@/components/audit/CheckCard";
import { ReportSection } from "@/components/audit/ReportSection";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AuditReport, CspPolicyView } from "@/domain/audit/model";

const keyDirectives = ["default-src", "script-src", "object-src", "base-uri", "frame-ancestors", "form-action"];
const riskySources = new Set(["'unsafe-inline'", "'unsafe-eval'", "*", "http:", "https:", "data:", "blob:"]);

function Source({ source }: { source: string }) {
    const risky = riskySources.has(source);
    return (
        <li>
            <code className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono text-xs ${risky ? "bg-warning-soft text-warning" : "bg-muted text-foreground"}`}>
                {risky && <TriangleAlert className="size-3" aria-hidden="true"/>}
                {source}
                {risky && <span className="sr-only"> (à surveiller)</span>}
            </code>
        </li>
    );
}

function PolicyTable({ policy, index }: { policy: CspPolicyView; index: number }) {
    const defined = new Set(policy.directives.map(({ name }) => name));
    const missing = keyDirectives.filter((name) => !defined.has(name));
    return (
        <div className="grid gap-3">
            <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-base">Politique {index + 1}</h3>
                <Badge variant={policy.mode === "enforce" ? "brand" : "secondary"}>
                    {policy.mode === "enforce" ? "Appliquée" : "Report-Only, non bloquante"}
                </Badge>
                <Badge variant="outline">{policy.source === "meta" ? "Balise meta" : "En-tête HTTP"}</Badge>
            </div>
            <div className="rounded-xl border">
                <Table>
                    <TableHeader>
                        <TableRow>
                            <TableHead scope="col">Directive</TableHead>
                            <TableHead scope="col">Sources</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {policy.directives.map(({ name, sources }) => (
                            <TableRow key={name}>
                                <TableHead scope="row" className="align-top font-mono text-xs font-semibold text-foreground">{name}</TableHead>
                                <TableCell className="whitespace-normal">
                                    {sources.length > 0
                                        ? <ul className="flex flex-wrap gap-1.5">{sources.map((source, position) => <Source key={`${source}-${position}`} source={source}/>)}</ul>
                                        : <span className="text-muted-foreground italic">Aucune source</span>}
                                </TableCell>
                            </TableRow>
                        ))}
                        {missing.map((name) => (
                            <TableRow key={name}>
                                <TableHead scope="row" className="font-mono text-xs font-semibold text-foreground">{name}</TableHead>
                                <TableCell className="text-muted-foreground italic">Non définie</TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </div>
        </div>
    );
}

export function CspAnalysis({ report }: { report: AuditReport }) {
    return (
        <ReportSection id="csp" title="Content Security Policy"
                       description="Analyse des en-têtes Content-Security-Policy et Content-Security-Policy-Report-Only, et des balises meta de l'en-tête HTML. Les directives ignorées en balise meta (frame-ancestors, report-uri, sandbox) ne sont pas retenues.">
            {report.csp.length === 0 ? (
                <Alert variant="danger">
                    <OctagonAlert aria-hidden="true"/>
                    <AlertTitle>Aucune CSP envoyée</AlertTitle>
                    <AlertDescription>La page ne transmet aucune politique de sécurité du contenu dans ses en-têtes.</AlertDescription>
                </Alert>
            ) : report.csp.map((policy, index) => <PolicyTable key={index} policy={policy} index={index}/>)}
            <CheckList label="Contrôles de la CSP" checks={report.checks.filter(({ category }) => category === "csp")}/>
        </ReportSection>
    );
}
