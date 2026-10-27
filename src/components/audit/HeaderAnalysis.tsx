import { CheckList } from "@/components/audit/CheckCard";
import { ReportSection } from "@/components/audit/ReportSection";
import { StatusBadge } from "@/components/audit/status";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AuditReport } from "@/domain/audit/model";

export function HeaderAnalysis({ report }: { report: AuditReport }) {
    const statuses = new Map(report.checks.map(({ id, status }) => [id, status]));
    const checks = report.checks.filter(({ category }) => category === "headers" || category === "cache");
    return (
        <ReportSection id="en-tetes" title="En-têtes HTTP"
                       description={report.response ? `En-têtes de la réponse ${report.response.method} ${report.response.status} reçue sur ${report.response.url}.` : "Aucune réponse HTTPS n'a pu être analysée."}>
            {report.headers.length > 0 && (
                <ScrollArea className="w-full rounded-xl border">
                    <Table className="min-w-xl print:min-w-0">
                        <TableHeader>
                            <TableRow>
                                <TableHead scope="col">En-tête</TableHead>
                                <TableHead scope="col">Valeur observée</TableHead>
                                <TableHead scope="col">État</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {report.headers.map(({ name, value, checkId }) => {
                                const status = checkId ? statuses.get(checkId) : undefined;
                                return (
                                    <TableRow key={name}>
                                        <TableHead scope="row" className="font-mono text-xs font-semibold text-foreground">{name}</TableHead>
                                        <TableCell className="max-w-md font-mono text-xs break-all whitespace-normal">
                                            {value ?? <span className="font-sans text-muted-foreground italic">Absent</span>}
                                        </TableCell>
                                        <TableCell>{status && <StatusBadge status={status}/>}</TableCell>
                                    </TableRow>
                                );
                            })}
                        </TableBody>
                    </Table>
                    <ScrollBar orientation="horizontal"/>
                </ScrollArea>
            )}
            <CheckList label="Contrôles des en-têtes" checks={checks}/>
        </ReportSection>
    );
}
