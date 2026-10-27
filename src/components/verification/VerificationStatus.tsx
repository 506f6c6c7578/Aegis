import { CircleCheck, Loader2, OctagonAlert, SearchX, TriangleAlert, type LucideIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import type { PendingReason } from "@/domain/verification/model";
import type { CheckState } from "@/hooks/use-verification";
import { formatCount, formatTime } from "@/lib/format";

const pendingMessages: Record<PendingReason, { title: string; description: string; icon: LucideIcon }> = {
    "not-found": {
        title: "Enregistrement introuvable pour l'instant",
        description: "La propagation DNS peut prendre quelques minutes. Vérifie le nom de l'enregistrement puis réessaie.",
        icon: SearchX
    },
    "mismatch": {
        title: "Valeur différente",
        description: "Un enregistrement TXT existe à ce nom, mais aucun ne contient le jeton attendu. Vérifie la valeur copiée.",
        icon: TriangleAlert
    },
    "dns-error": {
        title: "Résolution DNS indisponible",
        description: "Le résolveur n'a pas répondu. Réessaie dans quelques instants.",
        icon: TriangleAlert
    }
};

export function VerificationStatus({ check }: { check: CheckState }) {
    if (check.kind === "idle") return null;
    if (check.kind === "checking") {
        return (
            <Alert>
                <Loader2 className="animate-spin" aria-hidden="true"/>
                <AlertTitle>Vérification en cours</AlertTitle>
                <AlertDescription>Interrogation du résolveur DNS d'Aegis.</AlertDescription>
            </Alert>
        );
    }
    if (check.kind === "error") {
        return (
            <Alert variant="danger">
                <OctagonAlert aria-hidden="true"/>
                <AlertTitle>La vérification n'a pas abouti</AlertTitle>
                <AlertDescription>{check.message}</AlertDescription>
            </Alert>
        );
    }
    const { title, description, icon: Icon } = pendingMessages[check.reason];
    return (
        <Alert variant="warning">
            <Icon aria-hidden="true"/>
            <AlertTitle>{title}</AlertTitle>
            <AlertDescription>
                {description} {formatCount(check.attemptsRemaining, "tentative restante", "tentatives restantes")} pour ce challenge.
            </AlertDescription>
        </Alert>
    );
}

export function VerifiedStatus({ domain, expiresAt }: { domain: string; expiresAt: number }) {
    return (
        <Alert variant="success">
            <CircleCheck aria-hidden="true"/>
            <AlertTitle>Propriété vérifiée</AlertTitle>
            <AlertDescription>
                La preuve de propriété de {domain} est valable jusqu'à {formatTime(expiresAt)}, uniquement dans ce navigateur.
            </AlertDescription>
        </Alert>
    );
}
