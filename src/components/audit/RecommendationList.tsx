import { CircleCheck } from "lucide-react";
import { CheckDetails } from "@/components/audit/CheckCard";
import { ReportSection } from "@/components/audit/ReportSection";
import { PriorityBadge, StatusBadge } from "@/components/audit/status";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import type { AuditReport } from "@/domain/audit/model";
import { getRecommendations } from "@/domain/audit/recommendations";

export function RecommendationList({ report }: { report: AuditReport }) {
    const recommendations = getRecommendations(report.checks);
    return (
        <ReportSection id="recommandations" title="Recommandations"
                       description="Classées par priorité. Chaque point précise son impact et la correction à apporter.">
            {recommendations.length === 0 ? (
                <Alert variant="success">
                    <CircleCheck aria-hidden="true"/>
                    <AlertTitle>Aucune recommandation</AlertTitle>
                    <AlertDescription>Tous les contrôles applicables sont conformes.</AlertDescription>
                </Alert>
            ) : (
                <>
                    <ol className="hidden print:block print:space-y-4" aria-label="Recommandations détaillées">
                        {recommendations.map((check) => (
                            <li key={check.id} className="grid gap-2 border-b pb-4">
                                <p className="flex flex-wrap items-center gap-2">
                                    <span className="font-semibold text-foreground">{check.title}</span>
                                    <StatusBadge status={check.status}/>
                                    <PriorityBadge priority={check.priority}/>
                                </p>
                                <CheckDetails check={check}/>
                            </li>
                        ))}
                    </ol>
                    <Accordion type="multiple" className="rounded-xl border px-4 md:px-5 print:hidden">
                        {recommendations.map((check) => (
                            <AccordionItem key={check.id} value={check.id}>
                                <AccordionTrigger className="items-center gap-3 py-4 text-[0.9375rem] hover:no-underline">
                                    <span className="grid flex-1 gap-1.5 sm:flex sm:flex-wrap sm:items-center sm:gap-2">
                                        <span className="font-semibold text-foreground">{check.title}</span>
                                        <span className="flex flex-wrap gap-1.5">
                                            <StatusBadge status={check.status}/>
                                            <PriorityBadge priority={check.priority}/>
                                        </span>
                                    </span>
                                </AccordionTrigger>
                                <AccordionContent className="pb-4 text-[0.9375rem]">
                                    <CheckDetails check={check}/>
                                </AccordionContent>
                            </AccordionItem>
                        ))}
                    </Accordion>
                </>
            )}
        </ReportSection>
    );
}
