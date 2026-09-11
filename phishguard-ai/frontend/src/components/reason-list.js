/*
 * ThreatSight
 * Detection Signals Component
 */

export function renderReasonList(reasons = []) {

    if (!Array.isArray(reasons) || reasons.length === 0) {
        return `
            <div class="reasons-empty">
                <span class="reason-check">✓</span>
                <span>No suspicious indicators were identified.</span>
            </div>
        `;
    }

    return `
        <div class="reason-list">

            ${reasons.map(reason => `
                <div class="reason-item">

                    <div class="reason-icon">
                        !
                    </div>

                    <div class="reason-text">
                        ${escapeHtml(reason)}
                    </div>

                </div>
            `).join("")}

        </div>
    `;
}

function escapeHtml(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}