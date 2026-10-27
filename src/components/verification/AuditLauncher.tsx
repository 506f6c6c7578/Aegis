import { OctagonAlert, RotateCcw, ScanSearch } from "lucide-react";
import { useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
    AlertDialogTrigger
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { getReportPath } from "@/data/site";
import { useNow } from "@/hooks/use-now";
import { ApiError, api } from "@/lib/client/api";

const progressSteps = [
    { after: 0, label: "Résolution DNS et contrôle des adresses" },
    { after: 2_000, label: "Négociation TLS et lecture du certificat" },
    { after: 4_000, label: "Lecture des en-têtes et des redirections" },
    { after: 8_000, label: "Calcul du score et des recommandations" }
];

type LaunchState = { kind: "idle" } | { kind: "running"; startedAt: number } | { kind: "error"; message: string };

function ScanProgress({ startedAt }: { startedAt: number }) {
    const now = useNow(500);
    const elapsed = now - startedAt;
    const step = progressSteps.findLast(({ after }) => elapsed >= after) ?? progressSteps[0];
    return (
        <div className="grid gap-3" role="status" aria-live="polite">
            <Progress value={null} aria-label="Analyse en cours"/>
            <p className="text-sm font-semibold text-foreground">{step?.label}...</p>
        </div>
    );
}

export function AuditLauncher({ domain, onReset }: { domain: string; onReset: () => void }) {
    const [state, setState] = useState<LaunchState>({ kind: "idle" });

    const launch = async () => {
        setState({ kind: "running", startedAt: Date.now() });
        try {
            const { id } = await api.startAudit(domain);
            window.location.assign(getReportPath(id));
        } catch (error) {
            setState({ kind: "error", message: error instanceof ApiError ? error.message : "L'analyse n'a pas pu être lancée." });
        }
    };

    if (state.kind === "running") return <ScanProgress startedAt={state.startedAt}/>;

    return (
        <div className="grid gap-4">
            {state.kind === "error" && (
                <Alert variant="danger">
                    <OctagonAlert aria-hidden="true"/>
                    <AlertTitle>Analyse impossible</AlertTitle>
                    <AlertDescription>{state.message}</AlertDescription>
                </Alert>
            )}
            <div className="flex flex-wrap gap-3">
                <AlertDialog>
                    <AlertDialogTrigger asChild>
                        <Button size="lg">
                            <ScanSearch aria-hidden="true"/>
                            Lancer l'analyse
                        </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                        <AlertDialogHeader>
                            <AlertDialogTitle>Analyser {domain} ?</AlertDialogTitle>
                            <AlertDialogDescription>
                                Aegis va contacter uniquement https://{domain}/ et http://{domain}/, suivre au plus cinq redirections
                                dans ce domaine et lire les en-têtes des réponses, sans charger de ressource ni exécuter de JavaScript.
                            </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                            <AlertDialogCancel>Annuler</AlertDialogCancel>
                            <AlertDialogAction onClick={launch}>Lancer l'analyse</AlertDialogAction>
                        </AlertDialogFooter>
                    </AlertDialogContent>
                </AlertDialog>
                <Button variant="outline" size="lg" onClick={onReset}>
                    <RotateCcw aria-hidden="true"/>
                    Vérifier un autre domaine
                </Button>
            </div>
        </div>
    );
}
