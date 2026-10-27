import { OctagonAlert, SearchX } from "lucide-react";
import { ReportView } from "@/components/audit/ReportView";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { buttonVariants } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Toaster } from "@/components/ui/toast";
import { TooltipProvider } from "@/components/ui/tooltip";
import { pages } from "@/data/site";
import { useReport } from "@/hooks/use-report";

function ReportSkeleton() {
    return (
        <div className="grid gap-8" role="status" aria-label="Chargement du rapport">
            <div className="grid gap-3">
                <Skeleton className="h-4 w-32"/>
                <Skeleton className="h-10 w-2/3"/>
                <Skeleton className="h-14 w-full"/>
            </div>
            <Skeleton className="h-80 w-full rounded-xl"/>
            <Skeleton className="h-10 w-full"/>
            <div className="grid gap-3">
                <Skeleton className="h-28 w-full rounded-xl"/>
                <Skeleton className="h-28 w-full rounded-xl"/>
            </div>
        </div>
    );
}

const problemAppearance = {
    missing: { icon: SearchX, variant: "default" },
    error: { icon: OctagonAlert, variant: "danger" }
} as const;

function ReportProblem({ kind, title, description }: { kind: keyof typeof problemAppearance; title: string; description: string }) {
    const { icon: Icon, variant } = problemAppearance[kind];
    return (
        <div className="grid max-w-2xl gap-5">
            <h1 className="text-3xl">{title}</h1>
            <Alert variant={variant}>
                <Icon aria-hidden="true"/>
                <AlertTitle>{title}</AlertTitle>
                <AlertDescription>{description}</AlertDescription>
            </Alert>
            <a className={buttonVariants({ size: "lg", className: "w-fit" })} href={pages.verify}>Vérifier un domaine</a>
        </div>
    );
}

export function ReportPage({ id }: { id: string }) {
    const state = useReport(id);
    return (
        <TooltipProvider>
            {state.status === "loading" && <ReportSkeleton/>}
            {state.status === "ready" && <ReportView report={state.report}/>}
            {state.status === "missing" && (
                <ReportProblem kind="missing" title="Rapport introuvable"
                               description="Ce rapport a expiré ou a été généré dans une autre session. Les rapports ne sont conservés que 30 minutes, dans le navigateur qui a lancé l'analyse."/>
            )}
            {state.status === "error" && <ReportProblem kind="error" title="Chargement impossible" description={state.message}/>}
            <Toaster/>
        </TooltipProvider>
    );
}
