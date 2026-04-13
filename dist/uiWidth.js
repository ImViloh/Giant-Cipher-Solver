/**
 * Terminal box width for bordered CLI output.
 * Override with GIANT_UI_WIDTH (60–320). Default 160 fits long paths and hex rows.
 */
export function getUiWidth() {
    const raw = process.env.GIANT_UI_WIDTH;
    const n = raw !== undefined && raw !== "" ? Number.parseInt(raw, 10) : 160;
    if (!Number.isFinite(n))
        return 160;
    return Math.min(320, Math.max(60, n));
}
