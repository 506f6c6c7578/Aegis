import { ArrowRight, Loader2, OctagonAlert } from "lucide-react";
import { type SubmitEvent, useId, useState } from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { detectHostnameShapeError, hostnameErrorMessages, hostnameLimits } from "@/domain/domain/input";
import { useHydrated } from "@/hooks/use-hydrated";

interface DomainFormProps {
    submitting: boolean;
    serverError: string | null;
    onSubmit: (domain: string) => void;
}

export function DomainForm({ submitting, serverError, onSubmit }: DomainFormProps) {
    const inputId = useId();
    const hintId = useId();
    const errorId = useId();
    const [value, setValue] = useState("");
    const [localError, setLocalError] = useState<string | null>(null);
    const hydrated = useHydrated();
    const error = localError ?? serverError;

    const submit = (event: SubmitEvent<HTMLFormElement>) => {
        event.preventDefault();
        const domain = value.trim();
        const shapeError = detectHostnameShapeError(domain);
        setLocalError(shapeError ? hostnameErrorMessages[shapeError] : null);
        if (!shapeError) onSubmit(domain);
    };

    return (
        <form className="grid gap-4" onSubmit={submit} noValidate>
            <div className="grid gap-2">
                <label htmlFor={inputId} className="font-semibold text-foreground">Nom de domaine</label>
                <p id={hintId} className="text-sm text-muted-foreground">
                    Uniquement le nom d'hôte, sans https://, chemin ni port. Les noms internationalisés sont convertis automatiquement.
                </p>
                <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
                    <Input
                        id={inputId}
                        name="domain"
                        className="h-11 text-base"
                        placeholder="exemple.fr"
                        value={value}
                        onChange={(event) => {
                            setValue(event.target.value);
                            setLocalError(null);
                        }}
                        maxLength={hostnameLimits.inputMaxLength}
                        inputMode="url"
                        autoComplete="off"
                        autoCapitalize="none"
                        autoCorrect="off"
                        spellCheck={false}
                        required
                        aria-invalid={error ? true : undefined}
                        aria-describedby={error ? `${hintId} ${errorId}` : hintId}
                    />
                    <Button type="submit" size="lg" className="h-11 px-5" disabled={submitting || !hydrated}>
                        {submitting ? <Loader2 className="animate-spin" aria-hidden="true"/> : <ArrowRight aria-hidden="true"/>}
                        {submitting ? "Préparation..." : "Générer le challenge"}
                    </Button>
                </div>
            </div>
            <div id={errorId} aria-live="polite">
                {error && (
                    <Alert variant="danger">
                        <OctagonAlert aria-hidden="true"/>
                        <AlertDescription className="text-foreground">{error}</AlertDescription>
                    </Alert>
                )}
            </div>
        </form>
    );
}
