import { useEffect, useState } from "react";
import type { AuditReport } from "@/domain/audit/model";
import { ApiError, api } from "@/lib/client/api";

export type ReportState =
    | { status: "loading" }
    | { status: "ready"; report: AuditReport }
    | { status: "missing" }
    | { status: "error"; message: string };

export function useReport(id: string): ReportState {
    const [state, setState] = useState<ReportState>({ status: "loading" });

    useEffect(() => {
        const controller = new AbortController();
        api.getReport(id, controller.signal).then(
            (report) => setState({ status: "ready", report }),
            (error: unknown) => {
                if (controller.signal.aborted) return;
                if (error instanceof ApiError && error.status === 404) setState({ status: "missing" });
                else setState({ status: "error", message: error instanceof ApiError ? error.message : "Le rapport n'a pas pu être chargé." });
            }
        );
        return () => controller.abort();
    }, [id]);

    return state;
}
