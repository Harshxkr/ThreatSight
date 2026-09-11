/*
 * ThreatSight
 * Main Risk Card Component
 */

import {
    renderRiskMeter,
    getRiskLevel
} from "./risk-meter.js";

import {
    renderReasonList
} from "./reason-list.js";


function getVerdictText(verdict, level) {

    if (verdict) {

        const verdicts = {
            "LIKELY_PHISHING":
                "Likely phishing or fraudulent content",

            "LIKELY_FRAUD":
                "Likely fraudulent content",

            "MALICIOUS":
                "Potentially malicious content",

            "SUSPICIOUS":
                "Suspicious content detected",

            "SAFE":
                "No major threat detected"
        };

        if (verdicts[verdict]) {
            return verdicts[verdict];
        }
    }

    if (level === "LOW") {
        return "No major threat detected";
    }

    if (level === "SUSPICIOUS") {
        return "Suspicious activity detected";
    }

    return "Likely phishing or fraudulent content";
}


function getRiskDescription(level) {

    if (level === "LOW") {
        return "The analyzed content appears safe based on the available security indicators.";
    }

    if (level === "SUSPICIOUS") {
        return "Some indicators require caution before interacting with this content.";
    }

    return "Multiple security indicators associated with phishing, fraud or malicious activity were detected.";
}


function getSignalClass(value) {

    const score = Number(value) || 0;

    if (score <= 30) {
        return "low";
    }

    if (score <= 70) {
        return "suspicious";
    }

    return "high";
}


function renderSignal(name, value) {

    const score = Number(value) || 0;
    const className = getSignalClass(score);

    return `
        <div class="signal-item">

            <span>${name}</span>

            <strong class="${className}">
                ${score}%
            </strong>

        </div>
    `;
}


export function renderRiskCard(result = {}) {

    const score = Math.max(
        0,
        Math.min(
            100,
            Number(result.score) || 0
        )
    );

    const level =
        result.level ||
        getRiskLevel(score);

    const verdict =
        getVerdictText(
            result.verdict,
            level
        );

    const description =
        getRiskDescription(level);

    const reasons =
        result.reasons || [];

    const signals =
        result.signals || {};


    return `
        <div class="risk-card ${level.toLowerCase()}">

            <!-- Risk summary -->

            <div class="risk-summary">

                <div class="risk-ring"
                     style="--risk-percent: ${score}%">

                    <div class="risk-ring-inner">

                        <strong>
                            ${score}%
                        </strong>

                        <span>
                            THREAT RISK
                        </span>

                    </div>

                </div>


                <div class="risk-badge ${level.toLowerCase()}">
                    ${level === "HIGH" ? "🔴" :
                      level === "SUSPICIOUS" ? "🟠" : "🟢"}
                    ${level} RISK
                </div>


                <h2>
                    ${verdict}
                </h2>


                <p>
                    ${description}
                </p>

            </div>


            <!-- Detection Signals -->

            <div class="risk-section">

                <div class="section-heading">

                    <strong>
                        DETECTION SIGNALS
                    </strong>

                    <span>
                        ${reasons.length} indicators
                    </span>

                </div>


                ${renderReasonList(reasons)}

            </div>


            <!-- Signal summary -->

            <div class="risk-section">

                <div class="section-heading">

                    <strong>
                        SIGNAL ANALYSIS
                    </strong>

                </div>


                <div class="signal-grid">

                    ${renderSignal(
                        "NLP",
                        signals.nlp
                    )}

                    ${renderSignal(
                        "URL",
                        signals.url
                    )}

                    ${renderSignal(
                        "DOMAIN",
                        signals.domain
                    )}

                    ${renderSignal(
                        "BRAND",
                        signals.brand
                    )}

                </div>

            </div>


            <!-- Assessment -->

            <div class="assessment">

                <div class="assessment-title">
                    ASSESSMENT
                </div>

                <p>
                    ${escapeHtml(
                        result.assessment ||
                        description
                    )}
                </p>

            </div>


            <!-- Technical Evidence -->

            <button
                class="technical-button"
                id="technical-evidence-button"
            >

                <span>
                    VIEW TECHNICAL EVIDENCE
                </span>

                <span>
                    →
                </span>

            </button>

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