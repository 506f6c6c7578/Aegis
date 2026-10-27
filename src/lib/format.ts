const locale = "fr-FR";
const timeZone = "Europe/Paris";

const dateFormatter = new Intl.DateTimeFormat(locale, { timeZone: "UTC", day: "numeric", month: "long", year: "numeric" });
const dateTimeFormatter = new Intl.DateTimeFormat(locale, { timeZone, dateStyle: "long", timeStyle: "short" });
const timeFormatter = new Intl.DateTimeFormat(locale, { timeZone, hour: "2-digit", minute: "2-digit" });
const secondsFormatter = new Intl.NumberFormat(locale, { maximumFractionDigits: 1 });
const integerFormatter = new Intl.NumberFormat(locale, { maximumFractionDigits: 0 });

export function formatDate(isoDate: string): string {
    return dateFormatter.format(new Date(`${isoDate}T00:00:00Z`));
}

export function formatDateTime(timestamp: number): string {
    return dateTimeFormatter.format(timestamp);
}

export function formatTime(timestamp: number): string {
    return timeFormatter.format(timestamp);
}

export function formatDuration(milliseconds: number): string {
    return milliseconds < 1_000
        ? `${integerFormatter.format(milliseconds)} ms`
        : `${secondsFormatter.format(milliseconds / 1_000)} s`;
}

export function formatCount(count: number, singular: string, plural: string): string {
    return `${integerFormatter.format(count)} ${count > 1 ? plural : singular}`;
}

export function formatDays(days: number): string {
    return formatCount(days, "jour", "jours");
}
