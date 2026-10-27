type LogLevel = "info" | "warn" | "error";
type LogValue = string | number | boolean;

const writers: Record<LogLevel, (line: string) => void> = {
    info: (line) => console.log(line),
    warn: (line) => console.warn(line),
    error: (line) => console.error(line)
};

export function logEvent(level: LogLevel, event: string, fields: Readonly<Record<string, LogValue>> = {}): void {
    writers[level](JSON.stringify({ time: new Date().toISOString(), level, event, ...fields }));
}
