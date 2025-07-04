function waitForElement(selector, timeout = 8000) {
  return new Promise((resolve, reject) => {
    const interval = 100;
    const maxAttempts = timeout / interval;
    let attempts = 0;

    const check = () => {
      const el = document.querySelector(selector);
      if (el) resolve(el);
      else if (++attempts > maxAttempts) reject(`Timeout waiting for ${selector}`);
      else setTimeout(check, interval);
    };

    check();
  });
}

function logInPage(message) {
  const existing = document.getElementById("phish-log");
  if (existing) existing.remove();

  const box = document.createElement("div");
  box.id = "phish-log";
  box.style.position = "fixed";
  box.style.top = "10px";
  box.style.right = "10px";
  box.style.zIndex = "10000";
  box.style.backgroundColor = "#ffffcc";
  box.style.border = "1px solid #999";
  box.style.padding = "8px";
  box.style.fontSize = "12px";
  box.style.fontFamily = "monospace";
  box.textContent = message;
  document.body.appendChild(box);
}

function extractEmailContent() {
  const mailElement = document.querySelector("div.a3s");
  const subjectElement = document.querySelector("h2.hP");
  const senderElement = document.querySelector(".gD");

  if (!mailElement || !subjectElement || !senderElement) {
    console.warn("⚠️ Missing elements in DOM");
    logInPage("❌ Could not find Gmail email elements.");
    return null;
  }

  return {
    content: mailElement.innerText || "",
    subject: subjectElement.innerText || "",
    from: senderElement.getAttribute("email") || senderElement.textContent || ""
  };
}

function injectResultBox(result) {
  if (document.getElementById("phish-result-box")) return;

  const box = document.createElement("div");
  box.id = "phish-result-box";
  box.style.marginTop = "10px";
  box.style.padding = "10px";
  box.style.border = "2px solid black";
  box.style.backgroundColor = result.isPhishingEmail ? "#ffdddd" : "#ddffdd";
  box.innerHTML = `
    <strong>${result.isPhishingEmail ? "🚨 Phishing Detected" : "✅ Safe Email"}</strong><br/>
    <b>Score:</b> ${result.suspiciousScore}<br/>
    ${result.reasons.map(r => `• ${r}`).join("<br/>")}
  `;

  const subject = document.querySelector("h2.hP");
  subject?.parentNode?.insertBefore(box, subject.nextSibling);
}

async function runPhishingCheck() {
  const data = extractEmailContent();
  if (!data) return;

  logInPage("📤 Sending email for phishing analysis...");

  try {
    const res = await fetch("https://stylus-identifier-bars-files.trycloudflare.com/api/check-email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });

    const result = await res.json();
    console.log("✅ Received phishing result:", result);
    logInPage(result.isPhishingEmail ? "🚨 Phishing Email Detected" : "✅ Safe Email");
    injectResultBox(result);
  } catch (err) {
    console.error("❌ Error calling phishing API:", err.message);
    logInPage("❌ Failed to fetch result: " + err.message);
  }
}

// Gmail dynamic routing: detect when an email is opened
let currentUrl = location.href;
setInterval(() => {
  if (location.href !== currentUrl) {
    currentUrl = location.href;
    console.log("🔁 Gmail URL changed, scanning in 1.5s...");
    setTimeout(() => {
      waitForElement("div.a3s", 8000)
        .then(runPhishingCheck)
        .catch(e => {
          console.warn(e);
          logInPage("⚠️ Email content not found.");
        });
    }, 1500);
  }
}, 1500);
