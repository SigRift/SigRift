/* cog-review PR-14: severity dual-coding helper.
 *
 * Exposes window.severityIcon(sev) — returns a short HTML snippet
 * containing a single shape glyph wrapped in <span class="severity-icon">.
 * The glyph is the *non-color* differentiator (Paivio dual-coding) so
 * colour-blind operators can distinguish critical / high / warning / info
 * without relying on the badge background colour.
 *
 * aria-hidden="true" on the glyph keeps screen-readers reading the
 * canonical text label, not the decorative shape.
 *
 * Hosted in its own file (rather than dashboard.js) because admin.html
 * does not load dashboard.js — only chart_utils.js + admin.js. Loading
 * this small shim from both templates is cheaper than restructuring the
 * admin bundle.
 *
 * Unknown / unrecognised severities return '' so the badge degrades
 * gracefully to text-only.
 */
(function() {
    "use strict";

    window.severityIcon = function(severity) {
        switch ((severity || "").toLowerCase()) {
            case "critical": return '<span class="severity-icon" aria-hidden="true">◆</span>';
            case "high":     return '<span class="severity-icon" aria-hidden="true">▲</span>';
            case "warning":  return '<span class="severity-icon" aria-hidden="true">⚠</span>';
            case "info":     return '<span class="severity-icon" aria-hidden="true">ⓘ</span>';
            default:         return '';
        }
    };
})();
