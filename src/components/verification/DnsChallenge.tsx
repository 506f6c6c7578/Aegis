import { Loader2, Pencil, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { CopyButton } from "@/components/ui/copy-button";
import { DnsHelp } from "@/components/verification/DnsHelp";
import { VerificationStatus } from "@/components/verification/VerificationStatus";
import type { IssuedChallenge } from "@/domain/verification/model";
import { useNow } from "@/hooks/use-now";
import type { CheckState } from "@/hooks/use-verification";
import { formatTime } from "@/lib/format";

interface DnsChallengeProps {
    challenge: IssuedChallenge;
    check: CheckState;
    onConfirm: () => void;
    onReset: () => void;
}

function RecordField({ label, value, confirmation }: { label: string; value: string; confirmation: string }) {
    return (
        <div className="grid gap-1.5">
            <dt className="text-sm font-semibold text-foreground">{label}</dt>
            <dd className="flex items-start gap-2">
                <code className="min-w-0 flex-1 rounded-lg border bg-muted px-3 py-2 font-mono text-sm break-all text-foreground select-all">{value}</code>
                <CopyButton value={value} label={label} confirmation={confirmation} className="mt-1 shrink-0"/>
            </dd>
        </div>
    );
}

function getRetryAt(check: CheckState): number | null {
    return check.kind === "pending" || check.kind === "error" ? check.retryAt : null;
}

export function DnsChallenge({ challenge, check, onConfirm, onReset }: DnsChallengeProps) {
    const retryAt = getRetryAt(check);
    const now = useNow(1_000, retryAt !== null);
    const waitSeconds = retryAt === null ? 0 : Math.ceil((retryAt - now) / 1_000);
    const checking = check.kind === "checking";
    const idn = challenge.displayDomain !== challenge.domain;

    return (
        <Card className="gap-6 [--card-spacing:--spacing(5)] md:[--card-spacing:--spacing(7)]">
            <CardHeader>
                <CardTitle><h2 className="text-xl">Prouve que tu contrôles ce domaine</h2></CardTitle>
                <CardDescription>
                    Crée l'enregistrement DNS ci-dessous. Le challenge expire à {formatTime(challenge.expiresAt)}.
                </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-6">
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl bg-brand-soft px-4 py-3">
                    <p className="grid gap-0.5">
                        <span className="text-sm">Domaine normalisé</span>
                        <span className="font-mono font-semibold break-all text-foreground" data-testid="normalized-domain">{challenge.domain}</span>
                        {idn && <span className="text-sm">Affiché : {challenge.displayDomain}</span>}
                    </p>
                    <Button variant="outline" size="sm" onClick={onReset}>
                        <Pencil aria-hidden="true"/>
                        Modifier le domaine
                    </Button>
                </div>
                <dl className="grid gap-4">
                    <RecordField label="Type" value="TXT" confirmation="Type copié"/>
                    <RecordField label="Nom de l'enregistrement" value={challenge.recordName} confirmation="Nom de l'enregistrement copié"/>
                    <RecordField label="Valeur" value={challenge.recordValue} confirmation="Valeur copiée"/>
                </dl>
                <div className="flex flex-wrap items-center justify-between gap-3">
                    <DnsHelp/>
                    <Button size="lg" onClick={onConfirm} disabled={checking || waitSeconds > 0}>
                        {checking ? <Loader2 className="animate-spin" aria-hidden="true"/> : <RefreshCw aria-hidden="true"/>}
                        {waitSeconds > 0 ? `Nouvel essai dans ${waitSeconds} s` : "Vérifier l'enregistrement"}
                    </Button>
                </div>
                <div aria-live="polite">
                    <VerificationStatus check={check}/>
                </div>
            </CardContent>
        </Card>
    );
}
