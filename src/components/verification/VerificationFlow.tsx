import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Toaster } from "@/components/ui/toast";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuditLauncher } from "@/components/verification/AuditLauncher";
import { DnsChallenge } from "@/components/verification/DnsChallenge";
import { DomainForm } from "@/components/verification/DomainForm";
import { VerifiedStatus } from "@/components/verification/VerificationStatus";
import { useVerification, type VerificationState } from "@/hooks/use-verification";

const steps = [
    { step: "domain", label: "Domaine" },
    { step: "challenge", label: "Enregistrement DNS" },
    { step: "verified", label: "Analyse" }
] as const satisfies readonly { step: VerificationState["step"]; label: string }[];

function StepIndicator({ current }: { current: (typeof steps)[number]["step"] }) {
    const currentIndex = steps.findIndex(({ step }) => step === current);
    return (
        <ol className="flex flex-wrap gap-x-6 gap-y-2 text-sm" aria-label="Étapes de la vérification">
            {steps.map(({ step, label }, index) => (
                <li key={step} aria-current={index === currentIndex ? "step" : undefined}
                    className={`flex items-center gap-2 ${index <= currentIndex ? "font-semibold text-foreground" : "text-muted-foreground"}`}>
                    <span className={`grid size-6 place-items-center rounded-full text-xs ${index <= currentIndex ? "bg-primary text-primary-foreground" : "bg-muted"}`}>
                        {index + 1}
                    </span>
                    {label}
                </li>
            ))}
        </ol>
    );
}

const cardClass = "gap-6 [--card-spacing:--spacing(5)] md:[--card-spacing:--spacing(7)]";

function VerificationSkeleton() {
    return (
        <div className="grid gap-6" role="status" aria-label="Chargement de la vérification">
            <div className="flex flex-wrap gap-x-6 gap-y-2">
                {steps.map(({ step }) => <Skeleton key={step} className="h-6 w-32 rounded-full"/>)}
            </div>
            <Card className={cardClass}>
                <CardHeader className="gap-2">
                    <Skeleton className="h-7 w-2/3"/>
                    <Skeleton className="h-4 w-1/2"/>
                </CardHeader>
                <CardContent className="grid gap-3">
                    <Skeleton className="h-5 w-40"/>
                    <Skeleton className="h-4 w-full"/>
                    <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
                        <Skeleton className="h-11"/>
                        <Skeleton className="h-11 sm:w-48"/>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}

export function VerificationFlow() {
    const { state, submitting, formError, submitDomain, confirm, reset } = useVerification();

    if (state.step === "loading") return <VerificationSkeleton/>;

    return (
        <TooltipProvider>
            <div className="grid gap-6">
                <StepIndicator current={state.step}/>
                {state.step === "domain" && (
                    <Card className={cardClass}>
                        <CardHeader>
                            <CardTitle><h2 className="text-xl">Quel domaine veux-tu analyser ?</h2></CardTitle>
                            <CardDescription>Aegis génère un jeton unique à publier dans un enregistrement DNS TXT.</CardDescription>
                        </CardHeader>
                        <CardContent>
                            <DomainForm submitting={submitting} serverError={formError} onSubmit={submitDomain}/>
                        </CardContent>
                    </Card>
                )}
                {state.step === "challenge" && (
                    <DnsChallenge challenge={state.challenge} check={state.check} onConfirm={confirm} onReset={reset}/>
                )}
                {state.step === "verified" && (
                    <Card className={cardClass}>
                        <CardHeader>
                            <CardTitle><h2 className="text-xl">Lancer l'analyse</h2></CardTitle>
                            <CardDescription>L'analyse porte uniquement sur la page d'accueil de {state.challenge.domain}.</CardDescription>
                        </CardHeader>
                        <CardContent className="grid gap-5">
                            <VerifiedStatus domain={state.challenge.domain} expiresAt={state.expiresAt}/>
                            <AuditLauncher domain={state.challenge.domain} onReset={reset}/>
                        </CardContent>
                    </Card>
                )}
            </div>
            <Toaster/>
        </TooltipProvider>
    );
}
