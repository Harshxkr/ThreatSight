const API_URL = "http://localhost:8000/analyze";

let card = null;
let timer = null;
let lastUrl = null;

function removeCard() {
  if (card) {
    card.remove();
    card = null;
  }
}

function levelClass(level) {
  return {
    LOW: "phishguard-low",
    SUSPICIOUS: "phishguard-medium",
    HIGH: "phishguard-high",
    CRITICAL: "phishguard-critical"
  }[level] || "phishguard-medium";
}

function showCard(x, y, data) {
  removeCard();

  card = document.createElement("div");
  card.className = "phishguard-card";

  const reasons = (data.reasons || [])
    .slice(0, 5)
    .map(reason => `<div class="phishguard-reason">⚠️ ${reason}</div>`)
    .join("");

  card.innerHTML = `
    <h3>🛡️ PhishGuard AI</h3>
    <div class="phishguard-score ${levelClass(data.level)}">
      ${data.score}/100
    </div>
    <strong>${data.level} RISK</strong>
    <div style="margin-top:10px">${reasons || "No major threat signals detected."}</div>
  `;

  document.body.appendChild(card);

  const left = Math.min(x + 12, window.innerWidth - 340);
  const top = Math.min(y + 12, window.innerHeight - 240);
  card.style.left = `${Math.max(8, left)}px`;
  card.style.top = `${Math.max(8, top)}px`;
}

async function analyzeLink(link, event) {
  const url = link.href;
  const text = link.innerText || link.textContent || "";

  if (!url || url === lastUrl) return;
  lastUrl = url;

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url, text})
    });

    if (!response.ok) throw new Error("API error");

    const data = await response.json();
    showCard(event.clientX, event.clientY, data);
  } catch (error) {
    console.warn("PhishGuard backend unavailable:", error);
  }
}

document.addEventListener("mouseover", (event) => {
  const link = event.target.closest("a[href]");
  if (!link) return;

  clearTimeout(timer);
  timer = setTimeout(() => analyzeLink(link, event), 450);
});

document.addEventListener("mouseout", (event) => {
  if (event.target.closest("a[href]")) {
    clearTimeout(timer);
  }
});

document.addEventListener("scroll", removeCard, {passive: true});
