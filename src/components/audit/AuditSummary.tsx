import { Info } from "lucide-react";
import { AuditScore } from "@/components/audit/AuditScore";
import { statusAppearance } from "@/components/audit/status";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { categories, priorityLabels } from "@/domain/audit/labels";
import { type AuditReport, priorities } from "@/domain/audit/model";
import { priorityWeights } from "@/domain/audit/score";
import { formatDateTime, formatDuration } from "@/lib/format";

const numberFormatter = new Intl.NumberFormat("fr-FR", { maximumFractionDigits: 1 });

function ScoreMethod() {
    return (
        <Dialog>
            <DialogTrigger asChild>
                <Button variant="ghost" size="sm" className="print-hidden w-fit">
                    <Info aria-hidden="true"/>
                    Comment le score est calculé
                </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-lg">
                <DialogHeader>
                    <DialogTitle>Calcul du score indicatif</DialogTitle>
                    <DialogDescription>
                        Chaque catégorie dispose d'un poids. À l'intérieur d'une catégorie, chaque contrôle pèse selon sa priorité :
                        un contrôle conforme rapporte tous ses points, une recommandation la moitié, un problème aucun.
                    </DialogDescription>
                </DialogHeader>
                <ul className="grid gap-1.5 text-sm">
                    {Object.values(categories).map(({ label, weight }) => (
                        <li key={label} className="flex justify-between gap-4">
                            <span>{label}</span>
                            <span className="font-semibold text-foreground tabular-nums">{weight} points</span>
                        </li>
                    ))}
                </ul>
                <Separator/>
                <p className="text-sm">
                    Poids par priorité : {priorities.map((priority) => `${priorityLabels[priority].toLowerCase()} ${priorityWeights[priority]}`).join(", ")}.
                    Les contrôles non applicables et informatifs ne comptent pas. Une catégorie qui n'a pas pu être évaluée,
                    faute de réponse HTTPS, ne rapporte aucun point.
                </p>
                <p className="text-sm font-semibold text-foreground">
                    Ce score résume des bonnes pratiques observables de l'extérieur. Ce n'est ni une certification, ni une garantie de sécurité.
                </p>
            </DialogContent>
        </Dialog>
    );
}

function SummaryCounts({ report }: { report: AuditReport }) {
    const counts = [
        { status: "pass", label: "Contrôles conformes", value: report.summary.pass },
        { status: "warning", label: "Recommandations", value: report.summary.warning },
        { status: "fail", label: "Problèmes importants", value: report.summary.fail }
    ] as const;
    return (
        <dl className="grid grid-cols-3 gap-3">
            {counts.map(({ status, label, value }) => {
                const { icon: Icon, tone } = statusAppearance[status];
                return (
                    <div key={status} className="grid gap-1 rounded-lg bg-muted px-3 py-2.5">
                        <dt className="flex items-center gap-1.5 text-xs leading-tight">
                            <Icon className={`size-3.5 shrink-0 ${tone}`} aria-hidden="true"/>
                            {label}
                        </dt>
                        <dd className="font-heading text-2xl font-bold text-foreground tabular-nums">{value}</dd>
                    </div>
                );
            })}
        </dl>
    );
}

function CategoryBreakdown({ report }: { report: AuditReport }) {
    return (
        <ul className="grid gap-x-8 gap-y-4 md:grid-cols-2" aria-label="Détail du score par catégorie">
            {report.score.categories.map(({ id, weight, earned, evaluated }) => (
                <li key={id} className="grid gap-1.5">
                    <div className="flex justify-between gap-4 text-sm">
                        <span className="font-semibold text-foreground">{categories[id].label}</span>
                        <span className="tabular-nums">{evaluated ? `${numberFormatter.format(earned)} / ${weight}` : "Non évalué"}</span>
                    </div>
                    <Progress value={evaluated ? earned : 0} max={weight}
                              aria-label={`${categories[id].label} : ${evaluated ? `${numberFormatter.format(earned)} points sur ${weight}` : "non évalué"}`}/>
                </li>
            ))}
        </ul>
    );
}

export function AuditSummary({ report }: { report: AuditReport }) {
    const facts = [
        { label: "Domaine analysé", value: report.displayDomain === report.domain ? report.domain : `${report.displayDomain} (${report.domain})` },
        { label: "Date de l'analyse", value: formatDateTime(report.startedAt) },
        { label: "Durée", value: formatDuration(report.durationMs) }
    ];
    return (
        <Card className="gap-6 [--card-spacing:--spacing(5)] md:[--card-spacing:--spacing(7)]" role="region" aria-labelledby="resume-titre">
            <CardContent className="grid gap-6">
                <h2 id="resume-titre" className="text-xl">Résumé</h2>
                <div className="grid items-center gap-6 md:grid-cols-[auto_1fr]">
                    <AuditScore value={report.score.value}/>
                    <div className="grid gap-4">
                        <SummaryCounts report={report}/>
                        <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[auto_1fr]">
                            {facts.map(({ label, value }) => (
                                <div key={label} className="contents">
                                    <dt className="text-muted-foreground">{label}</dt>
                                    <dd className="font-semibold break-all text-foreground">{value}</dd>
                                </div>
                            ))}
                        </dl>
                    </div>
                </div>
                <Separator/>
                <CategoryBreakdown report={report}/>
                <div className="flex flex-wrap items-center justify-between gap-3">
                    <p className="text-sm text-muted-foreground">Score indicatif, sans valeur de certification ni garantie de sécurité.</p>
                    <ScoreMethod/>
                </div>
            </CardContent>
        </Card>
    );
}
