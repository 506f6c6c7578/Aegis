import { OctagonAlert } from "lucide-react";
import { CheckList, ObservedValue } from "@/components/audit/CheckCard";
import { FactList, ReportSection } from "@/components/audit/ReportSection";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import type { AuditReport, TlsFailureReason } from "@/domain/audit/model";
import { formatDateTime } from "@/lib/format";

const failureLabels: Record<TlsFailureReason, string> = {
    "expired": "Certificat expiré",
    "not-yet-valid": "Certificat pas encore valide",
    "hostname-mismatch": "Nom d'hôte non couvert par le certificat",
    "self-signed": "Certificat auto-signé",
    "untrusted-chain": "Chaîne de certificats non reconnue",
    "revoked": "Certificat révoqué",
    "handshake-failed": "Négociation TLS impossible",
    "connection-refused": "Port 443 fermé",
    "timeout": "Délai dépassé",
    "connection-failed": "Connexion interrompue"
};

const sectionCheckIds = new Set(["https-available", "certificate-chain", "certificate-hostname", "certificate-expiry", "hsts", "http-redirect", "tls-protocol", "tls-cipher"]);

function TlsFacts({ tls }: { tls: Extract<AuditReport["tls"], { status: "established" }> }) {
    const { certificate, chain } = tls;
    return (
        <FactList facts={[
            { label: "Protocole négocié", value: tls.protocol },
            { label: "Suite cryptographique", value: <ObservedValue value={tls.cipher}/> },
            { label: "Sujet", value: certificate.subject },
            { label: "Émetteur", value: certificate.issuer },
            { label: "Valide du", value: formatDateTime(certificate.validFrom) },
            { label: "Expire le", value: formatDateTime(certificate.validTo) },
            { label: "Noms couverts", value: certificate.subjectAltNames.join(", ") || "Non renseigné" },
            { label: "Clé publique", value: certificate.key ?? "Non renseignée" },
            { label: "Empreinte SHA-256", value: <ObservedValue value={certificate.fingerprint}/> },
            {
                label: "Chaîne",
                value: chain.length > 0
                    ? <ol className="grid gap-1 font-normal">{chain.map(({ subject, validTo }) => <li key={`${subject}-${validTo}`}>{subject}</li>)}</ol>
                    : "Aucun certificat intermédiaire transmis"
            }
        ]}/>
    );
}

export function TlsAnalysis({ report }: { report: AuditReport }) {
    const { tls } = report;
    return (
        <ReportSection id="tls" title="HTTPS et TLS"
                       description="Connexion établie sur le port 443 avec validation complète du certificat, sans test de versions ou de suites obsolètes.">
            {tls.status === "established" ? <TlsFacts tls={tls}/> : (
                <Alert variant="danger">
                    <OctagonAlert aria-hidden="true"/>
                    <AlertTitle>{failureLabels[tls.reason]}</AlertTitle>
                    <AlertDescription>La validation du certificat n'est jamais désactivée : Aegis s'arrête à l'erreur rencontrée.</AlertDescription>
                </Alert>
            )}
            <CheckList label="Contrôles HTTPS et TLS" checks={report.checks.filter(({ id }) => sectionCheckIds.has(id))}/>
        </ReportSection>
    );
}
