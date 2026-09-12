// ============================================================
// ThreatSight AI
// FINAL CONTENT SCRIPT
//
// SEPARATE ENGINES:
//
// 1. LINK ENGINE
//    - Existing hover detection
//    - Uses background.js -> backend
//    - Trusted official domains are not shown as phishing
//
// 2. EMAIL ENGINE
//    - Outlook only
//    - Only analyzes an opened/read email
//    - Does NOT analyze inbox preview rows
//    - Detects student/internship/placement scams
//    - Detects urgency + registration + opportunity bait
//    - Uses backend ML as an additional signal
//
// IMPORTANT:
// Do NOT modify background.js for this version.
// ============================================================


console.log("ThreatSight AI FINAL content.js loaded.");


// ============================================================
// CONFIGURATION
// ============================================================

const BACKEND_URL =
    "http://127.0.0.1:8000/analyze";

const LINK_HOVER_DELAY =
    450;

const EMAIL_SCAN_DELAY =
    1000;


// ============================================================
// STATE
// ============================================================

let linkHoverTimer =
    null;

let currentLink =
    null;

let emailScanTimer =
    null;

let lastEmailFingerprint =
    "";

let emailObserver =
    null;

let lastURL =
    location.href;


// ============================================================
// TRUSTED OFFICIAL DOMAINS
//
// These domains are NOT automatically phishing.
//
// This is intentionally separate from the email detector.
// A suspicious email can contain a legitimate Microsoft/Google
// form and still be suspicious because of social engineering.
// ============================================================

const TRUSTED_DOMAINS = [

    // Microsoft
    "microsoft.com",
    "office.com",
    "office365.com",
    "outlook.com",
    "live.com",
    "forms.office.com",

    // Google
    "google.com",
    "googleusercontent.com",
    "forms.gle",
    "docs.google.com",

    // Apple
    "apple.com",
    "icloud.com",

    // Amazon
    "amazon.com",

    // PayPal
    "paypal.com",

    // Meta
    "facebook.com",
    "instagram.com",

    // Professional services
    "linkedin.com",

    // Developer services
    "github.com",

    // Manipal
    "manipal.edu"

];


// ============================================================
// TRUSTED FORM DOMAINS
// ============================================================

const TRUSTED_FORM_DOMAINS = [

    "forms.office.com",
    "forms.gle",
    "docs.google.com",
    "typeform.com",
    "jotform.com"

];


// ============================================================
// DOMAIN NORMALIZATION
// ============================================================

function normalizeHostname(
    hostname
) {

    if (!hostname) {
        return "";
    }

    return hostname
        .toLowerCase()
        .trim()
        .replace(
            /^\.+|\.+$/g,
            ""
        );

}


function hostnameMatchesDomain(
    hostname,
    domain
) {

    hostname =
        normalizeHostname(
            hostname
        );

    domain =
        normalizeHostname(
            domain
        );

    return (
        hostname === domain ||
        hostname.endsWith(
            "." + domain
        )
    );

}


function isTrustedDomainFromURL(
    url
) {

    if (!url) {
        return false;
    }

    try {

        const parsed =
            new URL(url);

        const hostname =
            normalizeHostname(
                parsed.hostname
            );

        return TRUSTED_DOMAINS.some(
            domain =>
                hostnameMatchesDomain(
                    hostname,
                    domain
                )
        );

    } catch {

        return false;

    }

}


function isTrustedFormURL(
    url
) {

    if (!url) {
        return false;
    }

    try {

        const parsed =
            new URL(url);

        const hostname =
            normalizeHostname(
                parsed.hostname
            );

        return TRUSTED_FORM_DOMAINS.some(
            domain =>
                hostnameMatchesDomain(
                    hostname,
                    domain
                )
        );

    } catch {

        return false;

    }

}


// ============================================================
// SAFE HTML ESCAPE
// ============================================================

function escapeHTML(
    value
) {

    const div =
        document.createElement(
            "div"
        );

    div.textContent =
        String(value || "");

    return div.innerHTML;

}


// ============================================================
// LINK DETECTOR
// ============================================================

function isValidLink(
    link
) {

    if (!link) {
        return false;
    }

    if (!link.href) {
        return false;
    }

    const href =
        link.href.trim();

    if (!href) {
        return false;
    }

    if (
        href.startsWith(
            "javascript:"
        )
    ) {
        return false;
    }

    if (
        href.startsWith("#")
    ) {
        return false;
    }

    if (
        !href.startsWith(
            "http://"
        ) &&
        !href.startsWith(
            "https://"
        )
    ) {
        return false;
    }

    return true;

}


// ============================================================
// LINK CONTEXT
// ============================================================

function getLinkContext(
    link
) {

    if (!link) {
        return "";
    }

    const parent =
        link.parentElement;

    if (!parent) {
        return "";
    }

    return (
        parent.innerText ||
        ""
    )
        .replace(
            /\s+/g,
            " "
        )
        .trim()
        .substring(
            0,
            500
        );

}


// ============================================================
// LINK DATA
// ============================================================

function getLinkData(
    link
) {

    return {

        url:
            link.href || "",

        text:
            (
                link.innerText ||
                link.textContent ||
                ""
            )
                .replace(
                    /\s+/g,
                    " "
                )
                .trim()
                .substring(
                    0,
                    300
                ),

        context:
            getLinkContext(
                link
            )

    };

}


// ============================================================
// SEND LINK TO BACKGROUND
// ============================================================

function analyzeLink(
    link
) {

    if (
        !isValidLink(
            link
        )
    ) {
        return;
    }

    const data =
        getLinkData(
            link
        );

    console.log(
        "ThreatSight LINK:",
        data
    );

    chrome.runtime.sendMessage(

        {
            action:
                "ANALYZE_LINK",

            data:
                data
        },

        function(response) {

            if (
                chrome.runtime.lastError
            ) {

                console.log(
                    "ThreatSight link error:",
                    chrome.runtime.lastError.message
                );

                return;

            }

            if (!response) {
                return;
            }

            if (
                !response.success
            ) {
                return;
            }

            showLinkResult(
                response.result,
                data.url
            );

        }

    );

}


// ============================================================
// LINK RESULT
// ============================================================

function showLinkResult(
    result,
    url
) {

    removeLinkAlert();

    if (!result) {
        return;
    }


    // ========================================================
    // CRITICAL RULE:
    //
    // Official domains should not produce a phishing popup.
    //
    // This fixes:
    // google.com
    // safebrowsing.google.com
    // microsoft.com
    // forms.office.com
    // forms.gle
    // github.com
    // instagram.com
    //
    // The EMAIL engine can still flag the email containing
    // such a link.
    // ========================================================

    if (
        isTrustedDomainFromURL(
            url
        )
    ) {

        console.log(
            "ThreatSight: trusted official link ignored:",
            url
        );

        return;

    }


    const score =
        Number(
            result.score || 0
        );


    // Only display actual suspicious links.

    if (
        score < 30
    ) {
        return;
    }


    const level =
        result.level ||
        "SUSPICIOUS";


    let reasons =
        Array.isArray(
            result.reasons
        )
            ? result.reasons
            : [];


    reasons =
        [
            ...new Set(
                reasons
            )
        ];


    const alert =
        document.createElement(
            "div"
        );


    alert.id =
        "threatsight-link-alert";


    alert.innerHTML = `

        <div style="
            position:fixed;
            top:24px;
            right:24px;
            width:420px;
            max-height:75vh;
            overflow:auto;
            z-index:2147483647;
            background:#07111f;
            color:white;
            border:2px solid #ff4757;
            border-radius:18px;
            padding:22px;
            box-shadow:0 20px 60px rgba(0,0,0,.7);
            font-family:Arial,Helvetica,sans-serif;
        ">

            <button
                id="threatsight-link-close"
                style="
                    position:absolute;
                    right:12px;
                    top:7px;
                    background:none;
                    border:none;
                    color:#aaa;
                    font-size:27px;
                    cursor:pointer;
                "
            >×</button>

            <div style="
                font-size:21px;
                font-weight:bold;
                margin-bottom:12px;
            ">
                ⚠️ ThreatSight Alert
            </div>

            <div style="
                color:#ff4757;
                font-size:32px;
                font-weight:bold;
            ">
                Risk Score: ${score}/100
            </div>

            <div style="
                margin-top:5px;
                font-weight:bold;
                font-size:17px;
            ">
                ${escapeHTML(level)}
            </div>

            <div style="
                margin-top:15px;
                font-size:14px;
            ">
                This link may be suspicious.
            </div>

            <ul style="
                padding-left:22px;
                line-height:1.5;
                font-size:13px;
            ">

                ${
                    reasons
                        .slice(
                            0,
                            7
                        )
                        .map(
                            reason =>
                                `
                                <li style="
                                    margin-bottom:7px;
                                ">
                                    ${escapeHTML(
                                        reason
                                    )}
                                </li>
                                `
                        )
                        .join("")
                }

            </ul>

        </div>

    `;


    document.body.appendChild(
        alert
    );


    const close =
        document.getElementById(
            "threatsight-link-close"
        );


    if (close) {

        close.onclick =
            function() {

                removeLinkAlert();

            };

    }

}


// ============================================================
// REMOVE LINK ALERT
// ============================================================

function removeLinkAlert() {

    const old =
        document.getElementById(
            "threatsight-link-alert"
        );

    if (old) {
        old.remove();
    }

}


// ============================================================
// LINK HOVER LISTENER
// ============================================================

document.addEventListener(
    "mouseover",
    function(event) {

        const link =
            event.target.closest(
                "a"
            );

        if (!link) {
            return;
        }

        if (
            link ===
            currentLink
        ) {
            return;
        }

        currentLink =
            link;


        if (
            linkHoverTimer
        ) {

            clearTimeout(
                linkHoverTimer
            );

        }


        linkHoverTimer =
            setTimeout(
                function() {

                    analyzeLink(
                        link
                    );

                },
                LINK_HOVER_DELAY
            );

    },
    true
);


// ============================================================
// LINK MOUSE OUT
// ============================================================

document.addEventListener(
    "mouseout",
    function(event) {

        const link =
            event.target.closest(
                "a"
            );

        if (!link) {
            return;
        }

        if (
            linkHoverTimer
        ) {

            clearTimeout(
                linkHoverTimer
            );

            linkHoverTimer =
                null;
        }

    },
    true
);


// ============================================================
// OUTLOOK DETECTION
// ============================================================

function isOutlook() {

    const host =
        location.hostname
            .toLowerCase();

    return (
        host.includes(
            "outlook."
        ) ||
        host.includes(
            "outlook.office.com"
        ) ||
        host.includes(
            "office.com"
        ) ||
        host.includes(
            "live.com"
        )
    );

}


// ============================================================
// EMAIL TEXT CLEANING
// ============================================================

function cleanText(
    text
) {

    return (
        text || ""
    )
        .replace(
            /\u00a0/g,
            " "
        )
        .replace(
            /\s+/g,
            " "
        )
        .trim();

}


// ============================================================
// VISIBILITY
// ============================================================

function isVisible(
    element
) {

    if (!element) {
        return false;
    }

    const style =
        window.getComputedStyle(
            element
        );

    const rect =
        element.getBoundingClientRect();

    return (

        style.display !==
        "none"

        &&

        style.visibility !==
        "hidden"

        &&

        parseFloat(
            style.opacity || "1"
        ) > 0

        &&

        rect.width > 20

        &&

        rect.height > 20

    );

}


// ============================================================
// FIND OPENED OUTLOOK EMAIL
//
// IMPORTANT:
// We deliberately avoid grabbing the whole Outlook page.
//
// An inbox preview row usually has:
// - short text
// - sender
// - subject
//
// An opened email has:
// - sender
// - subject
// - large body
// - links
// - large reading pane
// ============================================================

function findOpenedEmailContainer() {

    if (
        !isOutlook()
    ) {
        return null;
    }


    const selectors = [

        '[role="main"]',

        '[role="document"]',

        '[aria-label*="Message body"]',

        '[aria-label*="message body"]',

        '[class*="ReadingPane"]',

        '[class*="readingPane"]',

        '[class*="reading-pane"]',

        '[class*="messageBody"]',

        '[class*="MessageBody"]'

    ];


    const candidates = [];


    // ========================================================
    // PASS 1:
    // Outlook-specific containers
    // ========================================================

    for (
        const selector of selectors
    ) {

        const elements =
            document.querySelectorAll(
                selector
            );


        for (
            const element of elements
        ) {

            if (
                !isVisible(
                    element
                )
            ) {
                continue;
            }


            const rect =
                element.getBoundingClientRect();


            const text =
                cleanText(
                    element.innerText
                );


            if (
                text.length < 250
            ) {
                continue;
            }


            // Reading pane should occupy
            // a meaningful part of screen.

            if (
                rect.width <
                window.innerWidth * 0.30
            ) {
                continue;
            }


            candidates.push({
                element,
                text,
                score:
                    text.length +
                    rect.width
            });

        }

    }


    // ========================================================
    // PASS 2:
    // Generic fallback
    // ========================================================

    if (
        candidates.length === 0
    ) {

        const elements =
            document.querySelectorAll(
                "main,article,section,div"
            );


        for (
            const element of elements
        ) {

            if (
                !isVisible(
                    element
                )
            ) {
                continue;
            }


            const rect =
                element.getBoundingClientRect();


            if (
                rect.width <
                window.innerWidth * 0.35
            ) {
                continue;
            }


            if (
                rect.left <
                window.innerWidth * 0.25
            ) {
                continue;
            }


            const text =
                cleanText(
                    element.innerText
                );


            if (
                text.length < 250 ||
                text.length > 20000
            ) {
                continue;
            }


            // Email body normally contains
            // an email address.

            if (
                !/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i
                    .test(text)
            ) {
                continue;
            }


            candidates.push({
                element,
                text,
                score:
                    text.length
            });

        }

    }


    if (
        candidates.length === 0
    ) {
        return null;
    }


    // Prefer the most compact meaningful
    // email container instead of entire page.

    candidates.sort(
        function(a, b) {

            return (
                b.score -
                a.score
            );

        }
    );


    return candidates[0].element;

}


// ============================================================
// FIND SENDER
// ============================================================

function findSender(
    container
) {

    if (!container) {
        return "";
    }


    // --------------------------------------------------------
    // mailto links
    // --------------------------------------------------------

    const mailLinks =
        container.querySelectorAll(
            'a[href^="mailto:"]'
        );


    for (
        const link of mailLinks
    ) {

        const href =
            link.getAttribute(
                "href"
            ) || "";


        const email =
            href
                .replace(
                    /^mailto:/i,
                    ""
                )
                .split("?")[0]
                .trim();


        if (
            /@/.test(
                email
            )
        ) {
            return email;
        }

    }


    // --------------------------------------------------------
    // Search visible text
    // --------------------------------------------------------

    const text =
        cleanText(
            container.innerText
        );


    const matches =
        text.match(
            /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/ig
        );


    if (
        matches &&
        matches.length > 0
    ) {

        return matches[0];

    }


    return "";

}


// ============================================================
// FIND SUBJECT
// ============================================================

function findSubject(
    container
) {

    if (!container) {
        return "";
    }


    const selectors = [

        "h1",
        "h2",
        "h3",

        '[role="heading"]',

        '[aria-level="1"]',
        '[aria-level="2"]',
        '[aria-level="3"]'

    ];


    for (
        const selector of selectors
    ) {

        const elements =
            container.querySelectorAll(
                selector
            );


        for (
            const element of elements
        ) {

            if (
                !isVisible(
                    element
                )
            ) {
                continue;
            }


            const text =
                cleanText(
                    element.innerText
                );


            if (
                text.length >= 3 &&
                text.length <= 300
            ) {

                return text;

            }

        }

    }


    return "";

}


// ============================================================
// EXTRACT LINKS FROM EMAIL
// ============================================================

function getEmailLinks(
    container
) {

    const links = [];


    if (!container) {
        return links;
    }


    const anchors =
        container.querySelectorAll(
            "a[href]"
        );


    for (
        const anchor of anchors
    ) {

        const href =
            anchor.href || "";


        if (
            !href.startsWith(
                "http://"
            ) &&
            !href.startsWith(
                "https://"
            )
        ) {
            continue;
        }


        links.push({

            url:
                href,

            text:
                cleanText(
                    anchor.innerText ||
                    anchor.textContent ||
                    ""
                )

        });

    }


    return links;

}


// ============================================================
// EXTRACT EMAIL
// ============================================================

function extractOpenedEmail() {

    const container =
        findOpenedEmailContainer();


    if (!container) {
        return null;
    }


    const body =
        cleanText(
            container.innerText
        );


    // ========================================================
    // IMPORTANT:
    //
    // Inbox rows are generally much shorter.
    // Require a real email-sized body.
    // ========================================================

    if (
        body.length < 250
    ) {
        return null;
    }


    const sender =
        findSender(
            container
        );


    if (
        !sender
    ) {
        return null;
    }


    const subject =
        findSubject(
            container
        );


    const links =
        getEmailLinks(
            container
        );


    return {

        sender,

        subject,

        body,

        links,

        container

    };

}


// ============================================================
// EMAIL HEURISTIC ENGINE
//
// This is specifically designed around the fake student mails
// shown in the screenshots:
//
// - FINAL ENROLLMENT NOTICE
// - internship
// - placement
// - student targeting
// - limited seats
// - registration form
// - apply here
// - certificate
// - NASSCOM / Skill India
// - urgency
// - no response
// - career opportunity
// ============================================================

function analyzeEmailHeuristics(
    email
) {

    const subject =
        email.subject
            .toLowerCase();


    const body =
        email.body
            .toLowerCase();


    const text =
        subject +
        " " +
        body;


    let score =
        0;


    const reasons =
        [];


    // ========================================================
    // 1. URGENCY
    // ========================================================

    const urgencyPatterns = [

        "urgent",
        "immediately",
        "act now",
        "final notice",
        "final warning",
        "final enrollment",
        "final update",
        "last chance",
        "last reminder",
        "important notice",
        "deadline",
        "expires",
        "expire",
        "today only",
        "respond immediately",
        "no response",
        "several reminders",
        "still there is no response",
        "do this today"

    ];


    const urgencyHits =
        urgencyPatterns.filter(
            word =>
                text.includes(
                    word
                )
        );


    if (
        urgencyHits.length >= 1
    ) {

        score += 15;

        reasons.push(
            "Uses urgency or pressure to make the recipient act quickly"
        );

    }


    if (
        urgencyHits.length >= 2
    ) {

        score += 10;

    }


    // ========================================================
    // 2. INTERNSHIP / CAREER
    // ========================================================

    const opportunityPatterns = [

        "internship",
        "intern",
        "training program",
        "training",
        "placement",
        "placements",
        "career opportunity",
        "career",
        "job opportunity",
        "job offer",
        "recruitment",
        "employment",
        "certification",
        "certificate",
        "career preparation",
        "skill india",
        "nasscom",
        "noc"

    ];


    const opportunityHits =
        opportunityPatterns.filter(
            word =>
                text.includes(
                    word
                )
        );


    if (
        opportunityHits.length >= 1
    ) {

        score += 15;

        reasons.push(
            "Uses internship, training, placement, or career-opportunity language"
        );

    }


    if (
        opportunityHits.length >= 2
    ) {

        score += 10;

    }


    // ========================================================
    // 3. STUDENT TARGETING
    // ========================================================

    const studentPatterns = [

        "dear student",
        "students",
        "student",
        "student id",
        "student details",
        "university",
        "college",
        "semester",
        "b.tech",
        "engineering",
        "academic",
        "academics",
        "department",
        "pursuing year",
        "campus placement",
        "campus"

    ];


    const studentHits =
        studentPatterns.filter(
            word =>
                text.includes(
                    word
                )
        );


    if (
        studentHits.length >= 2
    ) {

        score += 15;

        reasons.push(
            "Targets students using academic or placement-related language"
        );

    }


    // ========================================================
    // 4. REGISTRATION / APPLICATION
    // ========================================================

    const registrationPatterns = [

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
        "fill the form",
        "fill out the form",
        "submit the form",
        "join now",
        "apply below",
        "register below"

    ];


    const hasRegistration =
        registrationPatterns.some(
            word =>
                text.includes(
                    word
                )
        );


    if (
        hasRegistration
    ) {

        score += 18;

        reasons.push(
            "Directs the recipient to register, enroll, or submit an application"
        );

    }


    // ========================================================
    // 5. ONLINE FORM
    // ========================================================

    const hasForm =
        email.links.some(
            link =>
                isTrustedFormURL(
                    link.url
                )
        );


    if (
        hasForm
    ) {

        score += 10;

        reasons.push(
            "Contains an online registration or application form"
        );

    }


    // ========================================================
    // 6. SCARCITY
    // ========================================================

    const scarcityPatterns = [

        "limited seats",
        "limited seat",
        "limited slots",
        "limited availability",
        "seats available",
        "slots available",
        "only 10",
        "only 15",
        "only 20",
        "last date",
        "few seats",
        "few slots"

    ];


    if (
        scarcityPatterns.some(
            word =>
                text.includes(
                    word
                )
        )
    ) {

        score += 15;

        reasons.push(
            "Uses scarcity or limited-availability pressure"
        );

    }


    // ========================================================
    // 7. FEAR / CONSEQUENCE
    // ========================================================

    const fearPatterns = [

        "you will miss",
        "you may miss",
        "failure to",
        "if you do not",
        "otherwise",
        "your placement",
        "crucial for your placement",
        "lack practical knowledge",
        "become more hectic",
        "miss this opportunity",
        "lose this opportunity",
        "no response from your end"

    ];


    if (
        fearPatterns.some(
            word =>
                text.includes(
                    word
                )
        )
    ) {

        score += 12;

        reasons.push(
            "Uses fear of missing an opportunity or negative consequences"
        );

    }


    // ========================================================
    // 8. BENEFITS / REWARD BAIT
    // ========================================================

    const rewardPatterns = [

        "top companies",
        "top mncs",
        "placement assistance",
        "letter of recommendation",
        "career preparation",
        "growth opportunity",
        "industry-recognized",
        "career-defining",
        "job assistance",
        "guaranteed placement",
        "certificate from",
        "recognized certificate",
        "top product tech companies"

    ];


    const rewardHits =
        rewardPatterns.filter(
            word =>
                text.includes(
                    word
                )
        );


    if (
        rewardHits.length >= 2
    ) {

        score += 12;

        reasons.push(
            "Promises career, placement, certification, or other benefits"
        );

    }


    // ========================================================
    // 9. LINK + OPPORTUNITY
    // ========================================================

    if (
        opportunityHits.length > 0 &&
        email.links.length > 0
    ) {

        score += 10;

        reasons.push(
            "Combines an opportunity offer with an external link"
        );

    }


    // ========================================================
    // 10. STRONG SOCIAL ENGINEERING COMBINATION
    // ========================================================

    if (
        urgencyHits.length > 0 &&
        opportunityHits.length > 0 &&
        hasRegistration
    ) {

        score += 20;

        reasons.push(
            "Strong social-engineering pattern: opportunity bait + urgency + registration"
        );

    }


    // ========================================================
    // 11. STUDENT + INTERNSHIP + FORM
    // ========================================================

    if (
        studentHits.length >= 2 &&
        opportunityHits.length > 0 &&
        hasForm
    ) {

        score += 15;

        reasons.push(
            "Combines student targeting with an internship/career offer and online registration"
        );

    }


    return {

        score:
            Math.min(
                score,
                100
            ),

        reasons:
            reasons

    };

}


// ============================================================
// SENDER ANALYSIS
// ============================================================

function getSenderDomain(
    sender
) {

    if (
        !sender ||
        !sender.includes("@")
    ) {
        return "";
    }


    return sender
        .toLowerCase()
        .trim()
        .split("@")
        .pop()
        .replace(
            /[>),;:]+$/g,
            ""
        );

}


function isTrustedInstitutionalSender(
    sender
) {

    const domain =
        getSenderDomain(
            sender
        );


    if (!domain) {
        return false;
    }


    return (

        domain ===
        "manipal.edu"

        ||

        domain.endsWith(
            ".manipal.edu"
        )

    );

}


function analyzeSender(
    email
) {

    const sender =
        email.sender
            .toLowerCase();


    const domain =
        getSenderDomain(
            sender
        );


    const text =
        (
            email.subject +
            " " +
            email.body
        )
        .toLowerCase();


    let score =
        0;


    const reasons =
        [];


    // ========================================================
    // Trusted university domain
    // ========================================================

    if (
        isTrustedInstitutionalSender(
            sender
        )
    ) {

        reasons.push(
            "Sender belongs to a recognized institutional domain"
        );

    }


    // ========================================================
    // Generic mailbox used for institutional bait
    // ========================================================

    const genericDomains = [

        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "mail.com",
        "proton.me",
        "protonmail.com"

    ];


    const institutionalBait =
        /internship|placement|training|university|college|student|recruitment|job offer|career opportunity/i
            .test(
                text
            );


    if (
        genericDomains.includes(
            domain
        ) &&
        institutionalBait
    ) {

        score += 12;

        reasons.push(
            "Career or student opportunity is being sent from a generic email provider"
        );

    }


    return {

        score:
            Math.min(
                score,
                20
            ),

        reasons

    };

}


// ============================================================
// EMAIL URL ANALYSIS
//
// IMPORTANT:
// A genuine Microsoft/Google form is NOT itself malicious.
//
// We only use the presence of links as context.
// ============================================================

function analyzeEmailLinks(
    email
) {

    if (
        email.links.length === 0
    ) {

        return {

            score: 0,

            reasons: []

        };

    }


    let score =
        0;


    const reasons =
        [];


    score += 5;


    reasons.push(
        "Email contains a clickable link"
    );


    let externalCount =
        0;


    let suspiciousURLCount =
        0;


    for (
        const link of email.links
    ) {

        if (
            !isTrustedDomainFromURL(
                link.url
            )
        ) {

            externalCount++;

        }


        const lower =
            link.url.toLowerCase();


        const suspiciousPatterns = [

            "login",
            "signin",
            "verify",
            "verification",
            "password",
            "credential",
            "account",
            "payment",
            "billing",
            "authenticate"

        ];


        for (
            const pattern
            of suspiciousPatterns
        ) {

            if (
                lower.includes(
                    pattern
                )
            ) {

                suspiciousURLCount++;

                break;

            }

        }


        if (
            lower.startsWith(
                "http://"
            )
        ) {

            score += 8;

            reasons.push(
                "Email contains a link using HTTP instead of HTTPS"
            );

        }


        if (
            lower.length > 150
        ) {

            score += 5;

            reasons.push(
                "Email contains an unusually long URL"
            );

        }

    }


    if (
        externalCount > 0
    ) {

        score += 5;

    }


    if (
        suspiciousURLCount > 0
    ) {

        score += 10;

        reasons.push(
            "Email link contains security, account, verification, or payment-related URL patterns"
        );

    }


    return {

        score:
            Math.min(
                score,
                30
            ),

        reasons

    };

}


// ============================================================
// BACKEND ML EMAIL ANALYSIS
// ============================================================

async function analyzeEmailWithML(
    email
) {

    try {

        const firstURL =
            email.links.length > 0
                ? email.links[0].url
                : "https://example.com";


        const payload = {

            text:
                (
                    "SENDER: " +
                    email.sender +
                    "\nSUBJECT: " +
                    email.subject +
                    "\n\n" +
                    email.body
                )
                .substring(
                    0,
                    8000
                ),

            url:
                firstURL,

            context:
                "OUTLOOK_OPENED_EMAIL"

        };


        const response =
            await fetch(
                BACKEND_URL,
                {

                    method:
                        "POST",

                    headers: {

                        "Content-Type":
                            "application/json"

                    },

                    body:
                        JSON.stringify(
                            payload
                        )

                }
            );


        if (
            !response.ok
        ) {

            console.log(
                "ThreatSight ML HTTP error:",
                response.status
            );

            return null;

        }


        return await response.json();

    } catch (error) {

        console.log(
            "ThreatSight ML unavailable:",
            error
        );

        return null;

    }

}


// ============================================================
// FINAL EMAIL SCORE
// ============================================================

async function analyzeOpenedEmail() {

    if (
        !isOutlook()
    ) {
        return;
    }


    const email =
        extractOpenedEmail();


    if (!email) {
        return;
    }


    // ========================================================
    // FINGERPRINT
    // ========================================================

    const fingerprint =
        (
            email.sender +
            "|" +
            email.subject +
            "|" +
            email.body.substring(
                0,
                2500
            )
        );


    if (
        fingerprint ===
        lastEmailFingerprint
    ) {

        return;

    }


    lastEmailFingerprint =
        fingerprint;


    console.log(
        "ThreatSight opened email:",
        {
            sender:
                email.sender,

            subject:
                email.subject,

            links:
                email.links.length
        }
    );


    // ========================================================
    // LOCAL ANALYSIS
    // ========================================================

    const heuristic =
        analyzeEmailHeuristics(
            email
        );


    const sender =
        analyzeSender(
            email
        );


    const linkAnalysis =
        analyzeEmailLinks(
            email
        );


    // ========================================================
    // ML
    // ========================================================

    const ml =
        await analyzeEmailWithML(
            email
        );


    const mlScore =
        ml
            ? Number(
                ml.score || 0
            )
            : 0;


    // ========================================================
    // COMBINATION
    //
    // Heuristics are primary because your examples are
    // social-engineering emails rather than classic
    // password-stealing messages.
    // ========================================================

    let finalScore =

        (
            heuristic.score *
            0.55
        )

        +

        (
            linkAnalysis.score *
            0.10
        )

        +

        (
            sender.score *
            0.10
        )

        +

        (
            mlScore *
            0.25
        );


    finalScore =
        Math.round(
            finalScore
        );


    // ========================================================
    // STRONG PATTERN BOOSTS
    // ========================================================

    const emailText =
        (
            email.subject +
            " " +
            email.body
        )
        .toLowerCase();


    const hasInternship =
        /internship|training program|placement|career opportunity/i
            .test(
                emailText
            );


    const hasStudentTarget =
        /dear student|students|student id|university|college|semester|b\.tech|engineering/i
            .test(
                emailText
            );


    const hasRegistration =
        /apply here|apply now|register here|register now|registration form|enrollment|application form/i
            .test(
                emailText
            );


    const hasUrgency =
        /urgent|final notice|final warning|final enrollment|last chance|deadline|several reminders|no response|limited seats/i
            .test(
                emailText
            );


    // ========================================================
    // HIGH-CONFIDENCE STUDENT SCAM PATTERN
    // ========================================================

    if (
        hasInternship &&
        hasStudentTarget &&
        hasRegistration &&
        hasUrgency
    ) {

        finalScore =
            Math.max(
                finalScore,
                75
            );

    }


    // ========================================================
    // INTERNSHIP + STUDENT + LINK
    // ========================================================

    if (
        hasInternship &&
        hasStudentTarget &&
        email.links.length > 0
    ) {

        finalScore =
            Math.max(
                finalScore,
                55
            );

    }


    // ========================================================
    // IMPORTANT:
    //
    // DO NOT REDUCE SCORE JUST BECAUSE THE LINK IS:
    //
    // forms.office.com
    // forms.gle
    // google.com
    // microsoft.com
    //
    // Those can be legitimate destinations inside a
    // malicious/social-engineering email.
    // ========================================================


    // ========================================================
    // TRUSTED INSTITUTIONAL SENDER
    //
    // Do NOT blindly trust the sender.
    //
    // If an official institutional mailbox sends a genuinely
    // dangerous credential/phishing message, it still gets
    // analyzed.
    // ========================================================

    const dangerousSecurity =
        /password|passcode|otp|one[- ]time password|verification code|credential|credit card|card details|bank account|payment failed|account suspended|account locked|security code/i
            .test(
                emailText
            );


    if (
        isTrustedInstitutionalSender(
            email.sender
        ) &&
        !dangerousSecurity &&
        heuristic.score < 60
    ) {

        finalScore =
            Math.min(
                finalScore,
                35
            );

    }


    // ========================================================
    // FINAL LIMIT
    // ========================================================

    finalScore =
        Math.min(
            100,
            Math.max(
                0,
                finalScore
            )
        );


    // ========================================================
    // REASONS
    // ========================================================

    let reasons = [

        ...heuristic.reasons,

        ...sender.reasons,

        ...linkAnalysis.reasons

    ];


    // Only add ML reasons if they are meaningful.
    //
    // This prevents the model's generic
    // "high phishing probability" from dominating
    // the explanation.

    if (
        ml &&
        Array.isArray(
            ml.reasons
        ) &&
        mlScore >= 50
    ) {

        reasons.push(
            ...ml.reasons
        );

    }


    reasons =
        [
            ...new Set(
                reasons
            )
        ];


    console.log(
        "ThreatSight FINAL EMAIL SCORE:",
        finalScore
    );


    // ========================================================
    // SHOW
    // ========================================================

    if (
        finalScore >= 30
    ) {

        showEmailAlert(
            finalScore,
            reasons
        );

    } else {

        removeEmailAlert();

    }

}


// ============================================================
// EMAIL RISK LEVEL
// ============================================================

function emailRiskLevel(
    score
) {

    if (
        score < 30
    ) {
        return "LOW";
    }

    if (
        score < 60
    ) {
        return "SUSPICIOUS";
    }

    if (
        score < 80
    ) {
        return "HIGH";
    }

    return "CRITICAL";

}


// ============================================================
// EMAIL ALERT
// ============================================================

function showEmailAlert(
    score,
    reasons
) {

    removeEmailAlert();


    const level =
        emailRiskLevel(
            score
        );


    const alert =
        document.createElement(
            "div"
        );


    alert.id =
        "threatsight-email-alert";


    alert.innerHTML = `

        <div style="
            position:fixed;
            top:24px;
            right:24px;
            width:430px;
            max-height:80vh;
            overflow:auto;
            z-index:2147483647;
            background:#07111f;
            color:#ffffff;
            border:2px solid #ff4757;
            border-radius:18px;
            padding:23px;
            box-shadow:0 20px 70px rgba(0,0,0,.72);
            font-family:Arial,Helvetica,sans-serif;
        ">

            <button
                id="threatsight-email-close"
                style="
                    position:absolute;
                    top:7px;
                    right:12px;
                    background:none;
                    border:none;
                    color:#aaa;
                    font-size:28px;
                    cursor:pointer;
                "
            >
                ×
            </button>


            <div style="
                font-size:21px;
                font-weight:bold;
                margin-bottom:12px;
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
                margin-top:5px;
                font-size:17px;
                font-weight:bold;
            ">
                ${escapeHTML(level)}
            </div>


            <div style="
                margin-top:17px;
                background:#111c2c;
                border-radius:10px;
                padding:13px;
                font-size:14px;
                font-weight:bold;
            ">
                🚨 Suspicious email detected
            </div>


            <div style="
                margin-top:18px;
                font-size:14px;
                font-weight:bold;
            ">
                Why ThreatSight flagged it:
            </div>


            <ul style="
                padding-left:22px;
                margin-top:10px;
                line-height:1.55;
                font-size:13px;
            ">

                ${
                    reasons
                        .slice(
                            0,
                            9
                        )
                        .map(
                            reason =>
                                `
                                <li style="
                                    margin-bottom:8px;
                                ">
                                    ${escapeHTML(
                                        reason
                                    )}
                                </li>
                                `
                        )
                        .join("")
                }

            </ul>


            <div style="
                margin-top:18px;
                padding-top:13px;
                border-top:1px solid #334155;
                color:#94a3b8;
                font-size:11px;
                line-height:1.5;
            ">
                ThreatSight combines machine learning,
                social-engineering analysis, sender analysis,
                and URL analysis.
            </div>

        </div>

    `;


    document.body.appendChild(
        alert
    );


    const close =
        document.getElementById(
            "threatsight-email-close"
        );


    if (close) {

        close.onclick =
            function() {

                removeEmailAlert();

            };

    }

}


// ============================================================
// REMOVE EMAIL ALERT
// ============================================================

function removeEmailAlert() {

    const old =
        document.getElementById(
            "threatsight-email-alert"
        );


    if (old) {
        old.remove();
    }

}


// ============================================================
// EMAIL SCAN SCHEDULER
// ============================================================

function scheduleEmailScan() {

    if (
        emailScanTimer
    ) {

        clearTimeout(
            emailScanTimer
        );

    }


    emailScanTimer =
        setTimeout(
            function() {

                analyzeOpenedEmail();

            },
            EMAIL_SCAN_DELAY
        );

}


// ============================================================
// OUTLOOK OBSERVER
// ============================================================

function startOutlookObserver() {

    if (
        !isOutlook()
    ) {
        return;
    }


    console.log(
        "ThreatSight Outlook detector active."
    );


    // ========================================================
    // Initial scan
    // ========================================================

    setTimeout(
        function() {

            analyzeOpenedEmail();

        },
        1800
    );


    // ========================================================
    // DOM observer
    //
    // Outlook is a SPA, so opening an email often changes
    // the DOM without changing the page URL.
    // ========================================================

    emailObserver =
        new MutationObserver(
            function() {

                scheduleEmailScan();

            }
        );


    if (
        document.body
    ) {

        emailObserver.observe(
            document.body,
            {

                childList:
                    true,

                subtree:
                    true

            }
        );

    }


    // ========================================================
    // URL watcher
    // ========================================================

    setInterval(
        function() {

            if (
                location.href !==
                lastURL
            ) {

                lastURL =
                    location.href;


                lastEmailFingerprint =
                    "";


                removeEmailAlert();


                setTimeout(
                    function() {

                        analyzeOpenedEmail();

                    },
                    1300
                );

            }

        },
        700
    );


    // ========================================================
    // Click watcher
    //
    // Opening an email usually causes a click followed by
    // Outlook DOM updates.
    // ========================================================

    document.addEventListener(
        "click",
        function() {

            scheduleEmailScan();

        },
        true
    );

}


// ============================================================
// START
// ============================================================

if (
    isOutlook()
) {

    startOutlookObserver();

}


console.log(
    "ThreatSight AI FINAL content.js ready."
);