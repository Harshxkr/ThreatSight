// ==========================================
// ThreatSight AI - Content Script
// Person 1: Browser Extension
// ==========================================

console.log("ThreatSight AI is active on this page.");


// ==========================================
// Configuration
// ==========================================

const HOVER_DELAY = 400;

let hoverTimer = null;
let currentLink = null;


// ==========================================
// Get surrounding text
// ==========================================

function getSurroundingText(link) {

    if (!link) {
        return "";
    }

    const parent = link.parentElement;

    if (!parent) {
        return "";
    }

    return parent.innerText
        .replace(/\s+/g, " ")
        .trim()
        .substring(0, 500);
}


// ==========================================
// Extract link information
// ==========================================

function getLinkData(link) {

    return {
        url: link.href || "",
        text: (link.innerText || link.textContent || "")
            .trim()
            .substring(0, 300),

        context: getSurroundingText(link)
    };
}


// ==========================================
// Check if link should be analyzed
// ==========================================

function isValidLink(link) {

    if (!link) {
        return false;
    }

    if (!link.href) {
        return false;
    }

    // Ignore empty links
    if (link.href.trim() === "") {
        return false;
    }

    // Ignore javascript links
    if (link.href.startsWith("javascript:")) {
        return false;
    }

    // Ignore page anchors
    if (link.href.startsWith("#")) {
        return false;
    }

    return true;
}


// ==========================================
// Send link data to background.js
// ==========================================

function sendForAnalysis(link) {

    if (!isValidLink(link)) {
        return;
    }

    const linkData = getLinkData(link);

    console.log(
        "ThreatSight analyzing:",
        linkData
    );


    chrome.runtime.sendMessage(

        {
            action: "ANALYZE_LINK",
            data: linkData
        },

        function (response) {

            if (chrome.runtime.lastError) {

                console.log(
                    "ThreatSight:",
                    chrome.runtime.lastError.message
                );

                return;
            }


            if (!response) {
                return;
            }


            console.log(
                "ThreatSight analysis result:",
                response
            );


            // Send result to the page UI
            if (response.success) {

                showThreatResult(
                    response.result
                );

            }

        }
    );
}


// ==========================================
// Show basic result on webpage
// ==========================================

function showThreatResult(result) {

    if (!result) {
        return;
    }


    // Remove previous warning
    const oldWarning =
        document.getElementById(
            "threatsight-warning"
        );

    if (oldWarning) {
        oldWarning.remove();
    }


    const score =
        Number(result.score || 0);


    // Only show warning for suspicious results
    if (score < 30) {
        return;
    }


    const warning =
        document.createElement("div");

    warning.id =
        "threatsight-warning";


    warning.className =
        "threatsight-warning";


    let level =
        result.level || "SUSPICIOUS";


    let reasons =
        result.reasons || [];


    if (!Array.isArray(reasons)) {
        reasons = [];
    }


    warning.innerHTML = `

        <button
            class="threatsight-close"
            id="threatsight-close"
        >
            ×
        </button>

        <div class="threatsight-warning-header">

            <span class="threatsight-warning-icon">
                ⚠️
            </span>

            <span class="threatsight-warning-title">
                ThreatSight Alert
            </span>

        </div>

        <div class="threatsight-warning-text">

            This link may be suspicious.

        </div>

        <div class="threatsight-risk-score">

            Risk Score: ${score}/100

        </div>

        <div class="threatsight-warning-text">

            ${level}

        </div>

        ${
            reasons.length > 0
            ? `
                <ul style="
                    margin: 8px 0 0 18px;
                    color: #b9c8d8;
                    font-size: 12px;
                    line-height: 1.5;
                ">
                    ${reasons
                        .slice(0, 4)
                        .map(reason =>
                            `<li>${escapeHTML(reason)}</li>`
                        )
                        .join("")}
                </ul>
            `
            : ""
        }

    `;


    document.body.appendChild(warning);


    // Close button

    const closeButton =
        document.getElementById(
            "threatsight-close"
        );


    if (closeButton) {

        closeButton.addEventListener(
            "click",
            function () {

                warning.remove();

            }
        );

    }
}


// ==========================================
// Basic HTML escaping
// ==========================================

function escapeHTML(value) {

    const div =
        document.createElement("div");

    div.textContent =
        String(value);

    return div.innerHTML;
}


// ==========================================
// Link Hover Detection
// ==========================================

document.addEventListener(
    "mouseover",

    function (event) {

        const link =
            event.target.closest("a");


        if (!link) {
            return;
        }


        if (!isValidLink(link)) {
            return;
        }


        // If already hovering same link
        if (currentLink === link) {
            return;
        }


        currentLink = link;


        // Cancel previous timer

        if (hoverTimer) {

            clearTimeout(hoverTimer);

        }


        // Wait before sending request

        hoverTimer = setTimeout(
            function () {

                sendForAnalysis(link);

            },
            HOVER_DELAY
        );

    }
);


// ==========================================
// Mouse Leave
// ==========================================

document.addEventListener(
    "mouseout",

    function (event) {

        const link =
            event.target.closest("a");


        if (!link) {
            return;
        }


        const relatedTarget =
            event.relatedTarget;


        // Still inside same link
        if (
            relatedTarget &&
            link.contains(relatedTarget)
        ) {

            return;

        }


        if (hoverTimer) {

            clearTimeout(hoverTimer);

            hoverTimer = null;

        }


        currentLink = null;

    }
);


// ==========================================
// Receive messages from popup/background
// ==========================================

chrome.runtime.onMessage.addListener(

    function (
        message,
        sender,
        sendResponse
    ) {

        if (
            message.action ===
            "GET_PAGE_DATA"
        ) {

            const links =
                Array.from(
                    document.querySelectorAll("a")
                )
                .slice(0, 100)
                .map(link =>
                    getLinkData(link)
                );


            sendResponse({

                success: true,

                page: {
                    url:
                        window.location.href,

                    title:
                        document.title,

                    links:
                        links
                }

            });

        }


        return true;

    }

);


console.log(
    "ThreatSight link monitoring started."
);
