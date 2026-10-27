export function AuditScore({ value }: { value: number }) {
    return (
        <div className="relative grid size-36 shrink-0 place-items-center" role="img" aria-label={`Score indicatif : ${value} sur 100`}>
            <svg className="absolute inset-0 -rotate-90" viewBox="0 0 120 120" aria-hidden="true">
                <circle className="fill-none stroke-brand-soft" cx="60" cy="60" r="52" strokeWidth="10"/>
                {value > 0 && (
                    <circle className="animate-draw fill-none stroke-brand" cx="60" cy="60" r="52" strokeWidth="10"
                            strokeLinecap="round" pathLength={1} strokeDasharray={`${value / 100} 1`}/>
                )}
            </svg>
            <p className="relative text-center leading-none" aria-hidden="true">
                <span className="block font-heading text-4xl font-bold text-foreground tabular-nums">{value}</span>
                <span className="text-sm text-muted-foreground">sur 100</span>
            </p>
        </div>
    );
}
