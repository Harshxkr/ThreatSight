// ==========================================
// ThreatSight AI - Background Service Worker
// Person 1 - Browser Extension
// ==========================================


// ==========================================
// Backend Configuration
// ==========================================

const BACKEND_URL =
    "http://127.0.0.1:8000/analyze";


// ==========================================
// Extension Installed
// ==========================================

chrome.runtime.onInstalled.addListener(() => {

    console.log(
        "ThreatSight AI extension installed."
    );

});


// ==========================================
// Listen for messages from content.js
// ==========================================

chrome.runtime.onMessage.addListener(
    (message, sender, sendResponse) => {

        // --------------------------------------
        // Analyze hovered link
        // --------------------------------------

        if (message.action === "ANALYZE_LINK") {

            analyzeLink(message.data)
                .then(result => {

                    sendResponse({
                        success: true,
                        result: result
                    });

                })
                .catch(error => {

                    console.error(
                        "ThreatSight analysis error:",
                        error
                    );

                    sendResponse({
                        success: false,
                        error: "Unable to analyze link."
                    });

                });

            // Keep message channel open
            return true;
        }


        // --------------------------------------
        // Get current tab
        // --------------------------------------

        if (message.action === "GET_CURRENT_TAB") {

            chrome.tabs.query(
                {
                    active: true,
                    currentWindow: true
                },

                function (tabs) {

                    if (!tabs || tabs.length === 0) {

                        sendResponse({
                            success: false,
                            error: "No active tab found."
                        });

                        return;
                    }


                    sendResponse({

                        success: true,

                        tab: {
                            id: tabs[0].id,
                            url: tabs[0].url,
                            title: tabs[0].title
                        }

                    });

                }
            );

            return true;
        }

    }
);


// ==========================================
// Send link information to FastAPI
// ==========================================

async function analyzeLink(linkData) {

    console.log(
        "Sending link to ThreatSight backend:",
        linkData
    );


    const response = await fetch(
        BACKEND_URL,
        {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({

                url: linkData.url,

                text: linkData.text,

                context: linkData.context

            })
        }
    );


    // --------------------------------------
    // Check backend response
    // --------------------------------------

    if (!response.ok) {

        throw new Error(
            `Backend returned HTTP ${response.status}`
        );

    }


    const result =
        await response.json();


    console.log(
        "ThreatSight backend result:",
        result
    );


    return result;
}