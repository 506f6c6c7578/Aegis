import { CircleCheck, CircleMinus, OctagonAlert, TriangleAlert, type LucideIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { priorityLabels, statusLabels } from "@/domain/audit/labels";
import type { CheckStatus, Priority } from "@/domain/audit/model";

type BadgeVariant = "success" | "warning" | "danger" | "secondary" | "outline";

export const statusAppearance: Record<CheckStatus, { icon: LucideIcon; variant: BadgeVariant; tone: string }> = {
    "pass": { icon: CircleCheck, variant: "success", tone: "text-success" },
    "warning": { icon: TriangleAlert, variant: "warning", tone: "text-warning" },
    "fail": { icon: OctagonAlert, variant: "danger", tone: "text-danger" },
    "not-applicable": { icon: CircleMinus, variant: "secondary", tone: "text-muted-foreground" }
};

export function StatusBadge({ status }: { status: CheckStatus }) {
    const { icon: Icon, variant } = statusAppearance[status];
    return (
        <Badge variant={variant} data-status={status}>
            <Icon aria-hidden="true"/>
            {statusLabels[status]}
        </Badge>
    );
}

export function PriorityBadge({ priority }: { priority: Priority }) {
    return (
        <Badge variant="outline">
            <span className="sr-only">Priorité </span>
            {priorityLabels[priority]}
        </Badge>
    );
}
