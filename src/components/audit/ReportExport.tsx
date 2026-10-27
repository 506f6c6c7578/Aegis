import { Download, Printer } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "@/components/ui/toast";
import type { AuditReport } from "@/domain/audit/model";

function getExportFileName({ domain, startedAt }: AuditReport): string {
    return `aegis-${domain}-${new Date(startedAt).toISOString().slice(0, 10)}.json`;
}

function downloadJson(report: AuditReport): void {
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = getExportFileName(report);
    link.click();
    URL.revokeObjectURL(url);
    toast({ title: "Rapport exporté", description: "Le fichier JSON a été enregistré sur ton appareil.", variant: "success" });
}

export function ReportExport({ report }: { report: AuditReport }) {
    return (
        <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => downloadJson(report)}>
                <Download aria-hidden="true"/>
                Exporter en JSON
            </Button>
            <Button variant="ghost" onClick={() => window.print()}>
                <Printer aria-hidden="true"/>
                Imprimer ou PDF
            </Button>
        </div>
    );
}
