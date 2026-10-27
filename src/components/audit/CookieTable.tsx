import { Check, EyeOff, X } from "lucide-react";
import { CheckList } from "@/components/audit/CheckCard";
import { ReportSection } from "@/components/audit/ReportSection";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AuditReport, CookieView } from "@/domain/audit/model";
import { formatCount } from "@/lib/format";

const secondsPerDay = 86_400;

function Flag({ enabled }: { enabled: boolean }) {
    const Icon = enabled ? Check : X;
    return (
        <span className={`inline-flex items-center gap-1 ${enabled ? "text-success" : "text-danger"}`}>
            <Icon className="size-3.5" aria-hidden="true"/>
            {enabled ? "Oui" : "Non"}
        </span>
    );
}

function formatLifetime(lifetime: CookieView["lifetime"]): string {
    if (lifetime.kind === "session") return "Session";
    return lifetime.seconds < secondsPerDay
        ? formatCount(Math.max(1, Math.round(lifetime.seconds / 3_600)), "heure", "heures")
        : formatCount(Math.round(lifetime.seconds / secondsPerDay), "jour", "jours");
}

export function CookieTable({ report }: { report: AuditReport }) {
    const { cookies } = report;
    return (
        <ReportSection id="cookies" title="Cookies"
                       description="Cookies déposés par la page d'accueil, avec leurs attributs de sécurité.">
            <Alert variant="brand">
                <EyeOff aria-hidden="true"/>
                <AlertDescription>
                    Seuls le nom et les attributs sont conservés : la valeur des cookies n'est jamais lue, stockée ni affichée.
                </AlertDescription>
            </Alert>
            {cookies.length === 0 ? <p>Aucun cookie n'est déposé par la page d'accueil.</p> : (
                <div className="rounded-xl border">
                    <Table className="min-w-3xl print:min-w-0">
                        <TableHeader>
                            <TableRow>
                                {["Nom", "Secure", "HttpOnly", "SameSite", "Domain", "Path", "Durée"].map((label) => (
                                    <TableHead key={label} scope="col">{label}</TableHead>
                                ))}
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {cookies.map((cookie) => (
                                <TableRow key={`${cookie.name}|${cookie.domain ?? ""}|${cookie.path ?? ""}`}>
                                    <TableHead scope="row" className="font-mono text-xs font-semibold text-foreground">
                                        <span className="flex flex-wrap items-center gap-1.5">
                                            {cookie.name || "(sans nom)"}
                                            {cookie.sensitive && <Badge variant="outline">Sensible</Badge>}
                                        </span>
                                    </TableHead>
                                    <TableCell><Flag enabled={cookie.secure}/></TableCell>
                                    <TableCell><Flag enabled={cookie.httpOnly}/></TableCell>
                                    <TableCell>{cookie.sameSite ?? <span className="text-muted-foreground italic">Absent</span>}</TableCell>
                                    <TableCell className="font-mono text-xs">{cookie.domain ?? "Hôte exact"}</TableCell>
                                    <TableCell className="font-mono text-xs">{cookie.path ?? "/"}</TableCell>
                                    <TableCell>{formatLifetime(cookie.lifetime)}</TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </div>
            )}
            <CheckList label="Contrôles des cookies" checks={report.checks.filter(({ category }) => category === "cookies")}/>
        </ReportSection>
    );
}
