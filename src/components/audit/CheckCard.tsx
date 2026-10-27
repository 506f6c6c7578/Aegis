import { ArrowUpRight } from "lucide-react";
import { PriorityBadge, StatusBadge } from "@/components/audit/status";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { AuditCheck } from "@/domain/audit/model";

export function ObservedValue({ value }: { value: string }) {
    return <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs break-all text-foreground">{value}</code>;
}

export function CheckDetails({ check }: { check: AuditCheck }) {
    const { explanation, observed, recommendation, reference } = check;
    return (
        <div className="grid gap-2.5">
            <p>{explanation}</p>
            {observed && (
                <p className="text-sm">
                    <span className="font-semibold text-foreground">Observé : </span>
                    <ObservedValue value={observed}/>
                </p>
            )}
            {recommendation && (
                <p>
                    <span className="font-semibold text-foreground">Recommandation : </span>
                    {recommendation}
                </p>
            )}
            {reference && (
                <a className="inline-flex w-fit items-center gap-1 text-sm font-semibold text-brand underline-offset-4 hover:underline"
                   href={reference.url} target="_blank" rel="noopener noreferrer">
                    {reference.label}
                    <ArrowUpRight className="size-3.5" aria-hidden="true"/>
                    <span className="sr-only">(nouvel onglet)</span>
                </a>
            )}
        </div>
    );
}

export function CheckCard({ check }: { check: AuditCheck }) {
    return (
        <Card size="sm" className="gap-3 [--card-spacing:--spacing(4)] md:[--card-spacing:--spacing(5)]" data-check={check.id}>
            <CardHeader>
                <CardTitle>
                    <h3 className="text-base">{check.title}</h3>
                </CardTitle>
                <CardAction className="flex flex-wrap justify-end gap-1.5">
                    <StatusBadge status={check.status}/>
                    {check.status !== "not-applicable" && <PriorityBadge priority={check.priority}/>}
                </CardAction>
            </CardHeader>
            <CardContent className="text-[0.9375rem]">
                <CheckDetails check={check}/>
            </CardContent>
        </Card>
    );
}

export function CheckList({ checks, label }: { checks: readonly AuditCheck[]; label: string }) {
    return (
        <ul className="grid gap-3" aria-label={label}>
            {checks.map((check) => <li key={check.id}><CheckCard check={check}/></li>)}
        </ul>
    );
}
