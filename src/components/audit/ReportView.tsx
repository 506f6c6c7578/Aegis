import { ArrowLeft, Clock } from "lucide-react";
import type { ComponentType } from "react";
import { AuditSummary } from "@/components/audit/AuditSummary";
import { CookieTable } from "@/components/audit/CookieTable";
import { CspAnalysis } from "@/components/audit/CspAnalysis";
import { HeaderAnalysis } from "@/components/audit/HeaderAnalysis";
import { RecommendationList } from "@/components/audit/RecommendationList";
import { RedirectChain } from "@/components/audit/RedirectChain";
import { ReportExport } from "@/components/audit/ReportExport";
import { TlsAnalysis } from "@/components/audit/TlsAnalysis";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { buttonVariants } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { pages } from "@/data/site";
import type { AuditReport } from "@/domain/audit/model";
import { formatTime } from "@/lib/format";

const sections: readonly { value: string; label: string; component: ComponentType<{ report: AuditReport }> }[] = [
    { value: "recommandations", label: "Recommandations", component: RecommendationList },
    { value: "tls", label: "HTTPS et TLS", component: TlsAnalysis },
    { value: "en-tetes", label: "En-têtes", component: HeaderAnalysis },
    { value: "csp", label: "CSP", component: CspAnalysis },
    { value: "cookies", label: "Cookies", component: CookieTable },
    { value: "redirections", label: "Redirections", component: RedirectChain }
];

export function ReportView({ report }: { report: AuditReport }) {
    const recommendationCount = report.summary.warning + report.summary.fail;
    return (
        <div className="grid grid-cols-1 gap-8 print:block print:space-y-8">
            <header className="grid gap-4">
                <p className="eyebrow">Rapport d'analyse</p>
                <h1 className="text-3xl break-all md:text-4xl">{report.displayDomain}</h1>
                <Alert variant="brand" className="print-hidden">
                    <Clock aria-hidden="true"/>
                    <AlertDescription>
                        Rapport temporaire, visible uniquement dans ce navigateur. Il expire à {formatTime(report.expiresAt)} et
                        n'est jamais partagé ni conservé au-delà. Exporte-le pour le garder.
                    </AlertDescription>
                </Alert>
                <div className="print-hidden flex flex-wrap items-center justify-between gap-3">
                    <ReportExport report={report}/>
                    <a className={buttonVariants({ variant: "ghost" })} href={pages.verify}>
                        <ArrowLeft aria-hidden="true"/>
                        Retour à la vérification
                    </a>
                </div>
            </header>
            <AuditSummary report={report}/>
            <Tabs defaultValue="recommandations" className="gap-6">
                <TabsList variant="line" aria-label="Sections du rapport"
                          className="print-hidden h-auto! w-full flex-wrap justify-start gap-x-1 gap-y-2 border-b pb-1">
                    {sections.map(({ value, label }) => (
                        <TabsTrigger key={value} value={value} className="flex-none px-2.5 py-1.5">
                            {label}
                            {value === "recommandations" && <span className="text-muted-foreground tabular-nums">({recommendationCount})</span>}
                        </TabsTrigger>
                    ))}
                </TabsList>
                {sections.map(({ value, component: Section }) => (
                    <TabsContent key={value} value={value} forceMount className="min-w-0 data-[state=inactive]:hidden print:data-[state=inactive]:block">
                        <Section report={report}/>
                    </TabsContent>
                ))}
            </Tabs>
        </div>
    );
}
