/*
 * ThreatSight
 * Risk Meter Component
 *
 * Person 2 - Frontend
 *
 * Displays the visual threat-risk meter used
 * on the ThreatSight security analysis screen.
 */


// Determine the ThreatSight risk category
function getRiskLevel(score) {

    if (score <= 30) {
        return "LOW";
    }

    if (score <= 60) {
        return "SUSPICIOUS";
    }

    return "HIGH RISK";
}


// Convert the risk level into a CSS-friendly class
function getRiskClass(level) {

    return level
        .toLowerCase()
        .replace(/\s+/g, "-");
}


// Render the complete risk meter
export function renderRiskMeter(score, level = null) {

    // Make sure the score always stays between 0 and 100
    const safeScore = Math.max(
        0,
        Math.min(
            100,
            Number(score) || 0
        )
    );


    // Use the supplied level if the backend provides one.
    // Otherwise calculate it from the score.
    const riskLevel =
        level || getRiskLevel(safeScore);


    const riskClass =
        getRiskClass(riskLevel);


    return `

        <div class="risk-meter-container">

            <!-- Meter heading -->

            <div class="risk-meter-header">

                <span>
                    THREAT RISK
                </span>

                <strong>
                    ${safeScore}%
                </strong>

            </div>


            <!-- Main progress bar -->

            <div
                class="risk-meter"
                role="progressbar"
                aria-valuenow="${safeScore}"
                aria-valuemin="0"
                aria-valuemax="100"
                aria-label="Threat risk ${safeScore} percent"
            >

                <div
                    class="risk-meter-fill ${riskClass}"
                    style="width: ${safeScore}%"
                ></div>

            </div>


            <!-- Risk scale -->

            <div class="risk-scale">

                <span>
                    LOW
                </span>

                <span>
                    SUSPICIOUS
                </span>

                <span>
                    HIGH
                </span>

            </div>

        </div>

    `;
}


// Export the helper as well.
// The risk-card component can use it when needed.
export {
    getRiskLevel,
    getRiskClass
};