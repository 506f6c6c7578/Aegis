import type { ReactNode } from "react";

interface ReportSectionProps {
    id: string;
    title: string;
    description: string;
    children: ReactNode;
}

export function ReportSection({ id, title, description, children }: ReportSectionProps) {
    return (
        <section className="grid grid-cols-1 gap-5 print:block print:space-y-5" aria-labelledby={`${id}-titre`}>
            <header className="grid gap-1">
                <h2 id={`${id}-titre`} className="text-xl">{title}</h2>
                <p className="text-sm text-muted-foreground">{description}</p>
            </header>
            {children}
        </section>
    );
}

export function FactList({ facts }: { facts: readonly { label: string; value: ReactNode }[] }) {
    return (
        <dl className="grid gap-x-6 gap-y-2.5 rounded-xl border p-4 text-sm sm:grid-cols-[minmax(9rem,auto)_1fr] md:p-5">
            {facts.map(({ label, value }) => (
                <div key={label} className="contents">
                    <dt className="text-muted-foreground">{label}</dt>
                    <dd className="font-semibold break-words text-foreground">{value}</dd>
                </div>
            ))}
        </dl>
    );
}
