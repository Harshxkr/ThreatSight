// ==========================================
// ThreatSight AI - FINAL OUTLOOK EMAIL DETECTOR
// ==========================================

console.log("ThreatSight Outlook Detector active.");

const EMAIL_BACKEND = "http://127.0.0.1:8000/analyze";

let lastAnalyzedText = "";
let analysisTimer = null;


// ==========================================
// TRUSTED EXACT INSTITUTIONAL DOMAINS
// IMPORTANT: DO NOT TRUST generic .edu.in
// ==========================================

const TRUSTED_SENDER_DOMAINS = [
    "manipal.edu",
    "jaipur.manipal.edu",
    "microsoft.com",
    "google.com",
    "outlook.com",
    "office.com"
];


// ==========================================
// TRUSTED SENDER CHECK
// ==========================================

function isTrustedSender(email) {

    if (!email) return false;

    const match =
        email.toLowerCase().trim().match(
            /@([a-z0-9.-]+)$/i
        );

    if (!match) return false;

    const domain = match[1];

    return TRUSTED_SENDER_DOMAINS.some(
        trusted =>
            domain === trusted ||
            domain.endsWith("." + trusted)
    );
}


// ==========================================
// EXTRACT EMAIL ADDRESS
// ==========================================

function extractSender(container) {

    const mailLinks =
        Array.from(
            container.querySelectorAll(
                'a[href^="mailto:"]'
            )
        );

    for (const link of mailLinks) {

        const email =
            (link.getAttribute("href") || "")
                .replace(/^mailto:/i, "")
                .split("?")[0]
                .trim();

        if (email.includes("@")) {
            return email;
        }
    }


    const text =
        container.innerText || "";

    const matches =
        text.match(
            /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/ig
        );

    if (matches && matches.length > 0) {
        return matches[0];
    }

    return "";
}


// ==========================================
// FIND OPENED EMAIL
// ==========================================

function getEmailContainer() {

    const selectors = [

        '[role="document"]',

        '[aria-label*="Message body"]',

        '[aria-label*="message body"]',

        '[class*="ReadingPane"]',

        '[class*="readingPane"]',

        '[class*="reading-pane"]'

    ];


    for (const selector of selectors) {

        const elements =
            document.querySelectorAll(selector);

        for (const element of elements) {

            if (
                element &&
                element.innerText &&
                element.innerText.trim().length >= 40
            ) {

                return element;
            }
        }
    }

    return null;
}


// ==========================================
// EXTRACT OPENED EMAIL
// ==========================================

function extractEmail() {

    const container =
        getEmailContainer();

    if (!container) {
        return null;
    }


    const text =
        container.innerText
            .replace(/\s+/g, " ")
            .trim();


    if (text.length < 40) {
        return null;
    }


    let subject = "";

    const headings =
        container.querySelectorAll(
            "h1,h2,h3"
        );

    for (const heading of headings) {

        const value =
            heading.innerText
                .replace(/\s+/g, " ")
                .trim();

        if (value.length > 5) {

            subject =
                value.substring(0, 300);

            break;
        }
    }


    const links =
        Array.from(
            container.querySelectorAll(
                "a[href]"
            )
        )
        .map(link => ({
            text:
                (
                    link.innerText ||
                    link.textContent ||
                    ""
                )
                .replace(/\s+/g, " ")
                .trim(),

            url:
                link.href || ""
        }))
        .filter(link =>
            link.url.startsWith("http://") ||
            link.url.startsWith("https://")
        );


    return {

        subject,

        sender:
            extractSender(container),

        text,

        links

    };
}


// ==========================================
// LOCAL AI-STYLE EMAIL ANALYSIS
// ==========================================

function detectEmailThreats(email) {

    const combined =
        (
            email.subject +
            " " +
            email.text
        ).toLowerCase();


    let score = 0;

    const reasons = [];


    // ======================================
    // 1. URGENCY / PRESSURE
    // ======================================

    const urgencyWords = [

        "urgent",
        "important",
        "final notice",
        "final enrollment",
        "final update",
        "last reminder",
        "last chance",
        "immediately",
        "act now",
        "deadline",
        "limited time",
        "no response",
        "several reminders",
        "today only",
        "expires",
        "expire"

    ];


    const urgencyHits =
        urgencyWords.filter(
            word =>
                combined.includes(word)
        );


    if (urgencyHits.length >= 1) {

        score += 15;

        reasons.push(
            "Uses urgency or pressure to encourage immediate action"
        );
    }


    if (urgencyHits.length >= 2) {

        score += 10;

        reasons.push(
            "Uses multiple urgency or final-notice signals"
        );
    }


    // ======================================
    // 2. INTERNSHIP / JOB / CAREER BAIT
    // ======================================

    const opportunityWords = [

        "internship",
        "intern",
        "training",
        "training program",
        "career opportunity",
        "career",
        "placement",
        "placements",
        "job opportunity",
        "recruitment",
        "employment",
        "certification",
        "certificate",
        "noc",
        "work from home",
        "job offer",
        "offer letter"

    ];


    const opportunityHits =
        opportunityWords.filter(
            word =>
                combined.includes(word)
        );


    if (opportunityHits.length >= 1) {

        score += 10;

        reasons.push(
            "Contains internship, training, placement, or career-offer language"
        );
    }


    if (opportunityHits.length >= 2) {

        score += 10;
    }


    // ======================================
    // 3. STUDENT TARGETING
    // ======================================

    const studentWords = [

        "dear student",
        "student",
        "students",
        "college",
        "university",
        "semester",
        "academic",
        "academics",
        "b.tech",
        "engineering",
        "campus",
        "student id",
        "student details",
        "pursuing year",
        "department",
        "manipal"

    ];


    const studentHits =
        studentWords.filter(
            word =>
                combined.includes(word)
        );


    if (studentHits.length >= 2) {

        score += 10;

        reasons.push(
            "Targets students using academic or institutional language"
        );
    }


    // ======================================
    // 4. REGISTRATION / APPLICATION
    // ======================================

    const registrationWords = [

        "apply here",
        "apply now",
        "register here",
        "register now",
        "registration form",
        "registration",
        "application form",
        "application",
        "enrollment",
        "enroll now",
        "join now",
        "click here",
        "submit the form",
        "fill the form",
        "fill out the form"

    ];


    const registrationMatch =
        registrationWords.some(
            word =>
                combined.includes(word)
        );


    if (registrationMatch) {

        score += 15;

        reasons.push(
            "Directs the recipient to register, enroll, or submit an application"
        );
    }


    // ======================================
    // 5. ONLINE FORM
    // ======================================

    const formDomains = [

        "forms.gle",
        "docs.google.com/forms",
        "forms.office.com",
        "typeform.com",
        "jotform.com"

    ];


    const hasForm =
        email.links.some(link => {

            const url =
                link.url.toLowerCase();

            return formDomains.some(
                domain =>
                    url.includes(domain)
            );
        });


    if (hasForm) {

        score += 12;

        reasons.push(
            "Contains an online form or registration link"
        );
    }


    // ======================================
    // 6. ACTIONABLE LINK
    // ======================================

    if (email.links.length > 0) {

        score += 5;

        reasons.push(
            "Contains a clickable external link"
        );
    }


    // ======================================
    // 7. SUSPICIOUS LINK TEXT
    // ======================================

    const suspiciousLink =
        email.links.some(link => {

            const text =
                link.text.toLowerCase();

            return (

                text.includes("apply") ||
                text.includes("register") ||
                text.includes("verify") ||
                text.includes("enroll") ||
                text.includes("login") ||
                text.includes("click")

            );
        });


    if (suspiciousLink) {

        score += 10;

        reasons.push(
            "Contains a link encouraging the recipient to take an action"
        );
    }


    // ======================================
    // 8. SCARCITY
    // ======================================

    const scarcityWords = [

        "limited seats",
        "limited seat",
        "limited slots",
        "only 10",
        "only 15",
        "only 20",
        "seats available",
        "slots available",
        "limited availability",
        "last date",
        "final enrollment"

    ];


    const scarcityMatch =
        scarcityWords.some(
            word =>
                combined.includes(word)
        );


    if (scarcityMatch) {

        score += 15;

        reasons.push(
            "Uses scarcity or limited-availability pressure"
        );
    }


    // ======================================
    // 9. FEAR / CONSEQUENCES
    // ======================================

    const consequenceWords = [

        "you will miss",
        "you may miss",
        "failure to",
        "if you do not",
        "otherwise",
        "your placement",
        "crucial for your placement",
        "lack practical knowledge",
        "become more hectic"

    ];


    const consequenceMatch =
        consequenceWords.some(
            word =>
                combined.includes(word)
        );


    if (consequenceMatch) {

        score += 12;

        reasons.push(
            "Uses fear of missing an opportunity or negative consequences"
        );
    }


    // ======================================
    // 10. PERSONAL DATA
    // ======================================

    const personalDataWords = [

        "student id",
        "student name",
        "phone number",
        "mobile number",
        "date of birth",
        "address",
        "personal details",
        "student details",
        "resume",
        "cv"

    ];


    const personalDataHits =
        personalDataWords.filter(
            word =>
                combined.includes(word)
        );


    if (personalDataHits.length >= 2) {

        score += 15;

        reasons.push(
            "Contains multiple personal or student-detail fields"
        );
    }


    // ======================================
    // 11. REWARD / PROMISE BAIT
    // ======================================

    const rewardWords = [

        "top companies",
        "top mncs",
        "placement assistance",
        "letter of recommendation",
        "career preparation",
        "guaranteed",
        "growth opportunity",
        "job assistance",
        "industry-recognized",
        "career-defining"

    ];


    const rewardHits =
        rewardWords.filter(
            word =>
                combined.includes(word)
        );


    if (rewardHits.length >= 2) {

        score += 12;

        reasons.push(
            "Promises career, placement, certification, or other benefits"
        );
    }


    // ======================================
    // 12. SOCIAL ENGINEERING COMBINATION
    // ======================================

    if (
        opportunityHits.length >= 1 &&
        registrationMatch &&
        email.links.length > 0
    ) {

        score += 15;

        reasons.push(
            "Combines opportunity bait with an online action request"
        );
    }


    if (
        opportunityHits.length >= 1 &&
        studentHits.length >= 2 &&
        registrationMatch
    ) {

        score += 15;

        reasons.push(
            "Uses student-targeted career bait with a registration request"
        );
    }


    if (
        urgencyHits.length >= 1 &&
        opportunityHits.length >= 1 &&
        registrationMatch
    ) {

        score += 15;

        reasons.push(
            "Strong social-engineering pattern: urgency + opportunity bait + registration"
        );
    }


    // ======================================
    // 13. UNKNOWN SENDER PENALTY
    // ======================================
    //
    // Unknown sender is NOT automatically fraud.
    // But suspicious content from an untrusted
    // domain deserves extra attention.
    // ======================================

    const trusted =
        isTrustedSender(
            email.sender
        );


    if (
        !trusted &&
        score >= 35
    ) {

        score += 12;

        reasons.push(
            "Sender is not from a recognized trusted domain"
        );
    }


    // ======================================
    // 14. TRUSTED SENDER
    // ======================================
    //
    // Trusted sender reduces risk, but NEVER
    // overrides credential/payment phishing.
    // ======================================

    if (trusted) {

        const dangerousContent =
            /password|passcode|otp|one[- ]time password|verification code|credential|credit card|card details|bank account|payment failed|account suspended|account locked|security code/i
                .test(
                    combined
                );


        if (!dangerousContent) {

            score =
                Math.round(
                    score * 0.25
                );

            reasons.unshift(
                "Sender belongs to a recognized trusted institutional domain"
            );
        }
    }


    return {

        score:
            Math.min(
                score,
                100
            ),

        reasons

    };
}


// ==========================================
// BACKEND + LOCAL ANALYSIS
// ==========================================

async function analyzeEmail() {

    const email =
        extractEmail();


    if (!email) {
        return;
    }


    const fingerprint =
        email.sender +
        "|" +
        email.subject +
        "|" +
        email.text;


    if (
        fingerprint ===
        lastAnalyzedText
    ) {

        return;
    }


    lastAnalyzedText =
        fingerprint;


    console.log(
        "ThreatSight analyzing opened email:",
        email
    );


    const local =
        detectEmailThreats(
            email
        );


    console.log(
        "ThreatSight local score:",
        local
    );


    try {

        const response =
            await fetch(
                EMAIL_BACKEND,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({

                            url:
                                "https://example.com",

                            text:
                                (
                                    "SUBJECT: " +
                                    email.subject +
                                    "\n" +
                                    "SENDER: " +
                                    email.sender +
                                    "\n\n" +
                                    email.text
                                )
                                .substring(
                                    0,
                                    6000
                                ),

                            context: ""

                        })
                }
            );


        if (!response.ok) {

            throw new Error(
                "Backend returned HTTP " +
                response.status
            );
        }


        const ml =
            await response.json();


        const mlScore =
            Number(
                ml.score || 0
            );


        // ==================================
        // COMBINE TWO DETECTORS
        // ==================================

        let finalScore =
            Math.round(
                (
                    mlScore * 0.40
                ) +
                (
                    local.score * 0.60
                )
            );


        // ==================================
        // LOCAL HIGH-CONFIDENCE OVERRIDE
        // ==================================

        if (
            local.score >= 70
        ) {

            finalScore =
                Math.max(
                    finalScore,
                    60
                );
        }


        if (
            local.score >= 85
        ) {

            finalScore =
                Math.max(
                    finalScore,
                    75
                );
        }


        // ==================================
        // TRUSTED SENDER PROTECTION
        // ==================================

        if (
            isTrustedSender(
                email.sender
            )
        ) {

            const dangerousContent =
                /password|passcode|otp|one[- ]time password|verification code|credential|credit card|card details|bank account|payment failed|account suspended|account locked|security code/i
                    .test(
                        email.text
                    );


            if (!dangerousContent) {

                finalScore =
                    Math.min(
                        finalScore,
                        25
                    );
            }
        }


        finalScore =
            Math.min(
                finalScore,
                100
            );


        const reasons = [

            ...local.reasons,

            ...(Array.isArray(
                ml.reasons
            )
                ? ml.reasons
                : [])

        ];


        const uniqueReasons =
            [
                ...new Set(
                    reasons
                )
            ];


        const result = {

            score:
                finalScore,

            level:
                getRiskLevel(
                    finalScore
                ),

            reasons:
                uniqueReasons.slice(
                    0,
                    8
                )

        };


        console.log(
            "THREATSIGHT FINAL:",
            result
        );


        showEmailResult(
            result
        );


    } catch (error) {

        console.error(
            "ThreatSight backend error:",
            error
        );


        // Local detector continues working
        // even if backend is unavailable.

        if (
            local.score >= 40
        ) {

            showEmailResult({

                score:
                    local.score,

                level:
                    getRiskLevel(
                        local.score
                    ),

                reasons:
                    local.reasons.slice(
                        0,
                        8
                    )

            });
        }
    }
}


// ==========================================
// RISK LEVEL
// ==========================================

function getRiskLevel(score) {

    if (score <= 30) {
        return "LOW";
    }

    if (score <= 60) {
        return "SUSPICIOUS";
    }

    if (score <= 80) {
        return "HIGH";
    }

    return "CRITICAL";
}


// ==========================================
// SHOW ALERT
// ==========================================

function showEmailResult(result) {

    if (!result) {
        return;
    }


    const old =
        document.getElementById(
            "threatsight-email-warning"
        );


    if (old) {
        old.remove();
    }


    const score =
        Number(
            result.score || 0
        );


    if (
        score < 30
    ) {
        return;
    }


    const level =
        result.level ||
        getRiskLevel(
            score
        );


    const reasons =
        Array.isArray(
            result.reasons
        )
            ? result.reasons.slice(
                0,
                8
            )
            : [];


    const warning =
        document.createElement(
            "div"
        );


    warning.id =
        "threatsight-email-warning";


    warning.innerHTML = `

        <div style="
            position:fixed;
            top:24px;
            right:24px;
            width:430px;
            max-height:80vh;
            overflow:auto;
            z-index:2147483647;
            background:#07111f;
            color:white;
            border:2px solid #ff4757;
            border-radius:18px;
            padding:24px;
            box-shadow:0 15px 50px rgba(0,0,0,.55);
            font-family:Arial,sans-serif;
        ">

            <button
                id="threatsight-email-close"
                style="
                    position:absolute;
                    right:14px;
                    top:10px;
                    border:none;
                    background:none;
                    color:#aaa;
                    font-size:26px;
                    cursor:pointer;
                "
            >
                ×
            </button>


            <div style="
                font-size:21px;
                font-weight:bold;
                margin-bottom:14px;
            ">
                ⚠️ ThreatSight Email Alert
            </div>


            <div style="
                color:#ff4757;
                font-size:32px;
                font-weight:bold;
            ">
                Risk Score: ${score}/100
            </div>


            <div style="
                font-size:18px;
                font-weight:bold;
                margin:5px 0 18px;
            ">
                ${level}
            </div>


            <div style="
                background:#111c2c;
                border-radius:10px;
                padding:12px;
                margin-bottom:15px;
                font-size:13px;
            ">
                🚨 Suspicious email detected
            </div>


            <div style="
                font-size:14px;
                font-weight:bold;
                margin-bottom:8px;
            ">
                Why ThreatSight flagged it:
            </div>


            <ul style="
                padding-left:21px;
                margin-top:8px;
                color:#e2e8f0;
                font-size:13px;
                line-height:1.45;
            ">

                ${
                    reasons
                        .map(
                            reason =>
                                `<li style="margin-bottom:9px;">
                                    ${escapeHtml(
                                        String(reason)
                                    )}
                                </li>`
                        )
                        .join("")
                }

            </ul>


            <div style="
                margin-top:16px;
                padding-top:13px;
                border-top:1px solid #334155;
                font-size:12px;
                color:#94a3b8;
            ">
                ThreatSight combines ML,
                sender reputation, URL analysis,
                and social-engineering detection.
            </div>

        </div>

    `;


    document.body.appendChild(
        warning
    );


    const close =
        document.getElementById(
            "threatsight-email-close"
        );


    if (close) {

        close.addEventListener(
            "click",
            () => warning.remove()
        );
    }
}


// ==========================================
// ESCAPE HTML
// ==========================================

function escapeHtml(text) {

    const div =
        document.createElement(
            "div"
        );

    div.textContent =
        text;

    return div.innerHTML;
}


// ==========================================
// ANALYZE ONLY AFTER USER OPENS/CLICKS
// ==========================================

document.addEventListener(
    "click",
    function () {

        if (analysisTimer) {

            clearTimeout(
                analysisTimer
            );
        }


        analysisTimer =
            setTimeout(
                function () {

                    analyzeEmail();

                },
                1200
            );

    },
    true
);


// ==========================================
// ALSO DETECT OUTLOOK CONTENT CHANGES
// ==========================================

const observer =
    new MutationObserver(
        function () {

            if (analysisTimer) {
                clearTimeout(
                    analysisTimer
                );
            }


            analysisTimer =
                setTimeout(
                    function () {

                        analyzeEmail();

                    },
                    1500
                );
        }
    );


observer.observe(
    document.body,
    {
        childList: true,
        subtree: true
    }
);


// ==========================================
// CLEANUP
// ==========================================

window.addEventListener(
    "beforeunload",
    function () {

        if (analysisTimer) {

            clearTimeout(
                analysisTimer
            );
        }

        lastAnalyzedText = "";

    }
);