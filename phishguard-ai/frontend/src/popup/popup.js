/*
 * ThreatSight
 * Popup Controller
 *
 * Person 2 - Frontend
 *
 * This version runs in DEMO MODE.
 * The backend/API can be connected later.
 */


import {
    renderRiskCard
} from "../components/risk-card.js";


/* =====================================
   SCREEN MANAGEMENT
===================================== */

const screenIds = {

    home: "home-screen",

    scan: "scan-screen",

    result: "result-screen",

    evidence: "evidence-screen",

    error: "error-screen"

};


function showScreen(screenName) {

    Object.values(screenIds)
        .forEach(id => {

            const screen =
                document.getElementById(id);

            if (screen) {
                screen.classList.remove("active");
            }

        });


    const target =
        document.getElementById(
            screenIds[screenName]
        );


    if (target) {
        target.classList.add("active");
    }


    window.scrollTo(0, 0);
}


/* =====================================
   DEMO DATA
===================================== */

/*
 * This is temporary frontend data.
 *
 * Later this object will be replaced by
 * the response received from the AI backend.
 */

const demoResult = {

    score: 91,

    level: "HIGH",

    verdict: "LIKELY_PHISHING",

    signals: {

        nlp: 88,

        url: 94,

        domain: 91,

        brand: 76

    },

    reasons: [

        "Possible Microsoft impersonation",

        "Suspicious domain was detected",

        "Urgent language is present",

        "Sensitive information is requested",

        "Domain appears recently registered"

    ],

    assessment:
        "Multiple indicators associated with phishing and financial fraud were detected. The sender identity, domain characteristics, URL behavior and content patterns require caution.",

    recommendedAction:
        "Do not click links or provide sensitive information until the sender and destination are independently verified."

};


/* =====================================
   CURRENT ANALYSIS TYPE
===================================== */

let currentAnalysisType = "URL";


/* =====================================
   START ANALYSIS
===================================== */

function startAnalysis(type) {

    currentAnalysisType = type;


    const scanTitle =
        document.getElementById(
            "scan-title"
        );


    scanTitle.textContent =
        `Analyzing ${type}`;


    showScreen("scan");


    /*
     * DEMO SCANNING
     *
     * We wait 2 seconds to make the
     * frontend feel like a real analysis.
     *
     * Later:
     *
     * content/background
     *       ↓
     * backend API
     *       ↓
     * ML model
     *       ↓
     * result
     */

    setTimeout(
        () => {

            displayResult(
                demoResult
            );

        },
        2000
    );
}


/* =====================================
   DISPLAY RESULT
===================================== */

function displayResult(result) {

    const container =
        document.getElementById(
            "risk-card-container"
        );


    container.innerHTML =
        renderRiskCard(result);


    updateTarget();


    updateRecommendedAction(
        result
    );


    showScreen("result");


    /*
     * Technical evidence button
     * is created by risk-card.js,
     * so we attach its event after
     * the card has been rendered.
     */

    const evidenceButton =
        document.getElementById(
            "technical-evidence-button"
        );


    if (evidenceButton) {

        evidenceButton.addEventListener(
            "click",
            () => {

                showScreen("evidence");

            }
        );

    }

}


/* =====================================
   UPDATE TARGET
===================================== */

function updateTarget() {

    const typeElement =
        document.getElementById(
            "target-type"
        );


    const valueElement =
        document.getElementById(
            "target-value"
        );


    typeElement.textContent =
        `${currentAnalysisType.toUpperCase()} ANALYSIS`;


    if (currentAnalysisType === "Email") {

        valueElement.textContent =
            "security-alert@secure-account-check.xyz";

    }

    else if (
        currentAnalysisType === "Message"
    ) {

        valueElement.textContent =
            "Congratulations! You have been selected for a prize.";

    }

    else {

        valueElement.textContent =
            "https://secure-account-check.xyz/login";

    }

}


/* =====================================
   RECOMMENDED ACTION
===================================== */

function updateRecommendedAction(
    result
) {

    const element =
        document.getElementById(
            "recommended-text"
        );


    element.textContent =
        result.recommendedAction ||
        "Review the detected security indicators before interacting with this content.";

}


/* =====================================
   BACK BUTTONS
===================================== */

document
    .querySelectorAll("[data-back]")
    .forEach(button => {

        button.addEventListener(
            "click",
            () => {

                const destination =
                    button.dataset.back;


                if (
                    destination ===
                    "home-screen"
                ) {

                    showScreen("home");

                }

                else if (
                    destination ===
                    "result-screen"
                ) {

                    showScreen("result");

                }

            }
        );

    });


/* =====================================
   ANALYSIS BUTTONS
===================================== */

document
    .querySelectorAll(".analysis-card")
    .forEach(button => {

        button.addEventListener(
            "click",
            () => {

                const type =
                    button.dataset.type;

                startAnalysis(type);

            }
        );

    });


/* =====================================
   REPORT THREAT
===================================== */

const reportButton =
    document.getElementById(
        "report-threat"
    );


reportButton.addEventListener(
    "click",
    () => {

        showReportToast();

    }
);


function showReportToast() {

    const toast =
        document.getElementById(
            "toast"
        );


    toast.classList.add("show");


    setTimeout(
        () => {

            toast.classList.remove(
                "show"
            );

        },
        3000
    );

}


/* =====================================
   RETRY
===================================== */

document
    .getElementById("retry-button")
    .addEventListener(
        "click",
        () => {

            startAnalysis(
                currentAnalysisType
            );

        }
    );


/* =====================================
   BACKEND CHECK
===================================== */

/*
 * We keep this function because your
 * original popup already had backend
 * connectivity checking.
 *
 * It does NOT control the demo UI yet.
 *
 * Later we will connect the actual
 * /analyze endpoint here.
 */

async function checkBackend() {

    try {

        const response =
            await fetch(
                "http://127.0.0.1:8000/",
                {
                    method: "GET"
                }
            );


        if (response.ok) {

            console.log(
                "ThreatSight backend connected."
            );

            return true;

        }

    }

    catch (error) {

        console.log(
            "ThreatSight backend unavailable. Running frontend demo mode."
        );

    }


    return false;
}


/* =====================================
   INITIALIZATION
===================================== */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        showScreen("home");

        checkBackend();

    }
);