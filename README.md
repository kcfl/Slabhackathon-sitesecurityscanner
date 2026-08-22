# 🛡️ Site Security Scanner

An AI-powered web app that checks the public security posture of any website in seconds. Paste a URL, get an instant security score, and see exactly what to fix.

Built for **SLAB Hackathon 2026**, hosted by Coding Club at Samrat Ashok Technological Institute (SATI), Vidisha — a 20-campus hackathon series requiring every project to meaningfully integrate [WebCMD](https://github.com/agentrhq/webcmd).

---

## What it does

Enter any website URL and the scanner analyzes:

- **HTTPS enforcement** — is the connection secure?
- **Security headers** — Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options
- **Cookie configuration** — Secure, HttpOnly, and SameSite flags
- **Third-party script exposure** — external domains loading scripts on the page (detected via a real rendered browser, not just a raw HTTP request)

All of this raw data is sent to **Google's Gemini API**, which returns:
- An overall security score (0–100)
- A one-sentence verdict
- A prioritized "top fix"
- A detailed, categorized findings list with severity levels (high / medium / low) and specific, actionable recommendations

Results are displayed on a clean, color-coded dashboard.

---

## WebCMD Integration

This project uses [WebCMD](https://github.com/agentrhq/webcmd) — open-source browser infrastructure for AI agents — to detect third-party scripts loaded on a page.

We built a custom WebCMD adapter (`scanner/scripts`) that:
1. Opens a real, rendered browser session
2. Navigates to the target URL and waits for the page to fully load
3. Reads every `<script src>` tag actually present in the DOM after JavaScript executes
4. Filters out first-party scripts and returns only third-party domains

This step matters because a plain HTTP request only sees a site's *initial* response — it can't see scripts injected or loaded dynamically after the page renders. WebCMD lets us see the page the way a real visitor's browser does.

The adapter runs automatically on every scan, from the backend:

```js
const { stdout } = await execAsync(`webcmd scanner scripts --url "${targetUrl}" -f json`);
```

Its output feeds directly into the same AI analysis pipeline as the header/cookie checks, under a dedicated `third_party_scripts` category.

You can also run the adapter directly from the command line:

```bash
webcmd scanner scripts --url https://github.com -f json
```

---

## Tech Stack

- **Backend:** Node.js + Express
- **Browser automation:** [WebCMD](https://github.com/agentrhq/webcmd)
- **AI analysis:** Google Gemini API (`gemini-3.6-flash`, called directly via REST)
- **Frontend:** HTML + Tailwind CSS (via CDN), vanilla JavaScript

---

## Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) 20.6 or higher
- A [Gemini API key](https://aistudio.google.com/apikey)
- [WebCMD](https://github.com/agentrhq/webcmd) installed globally

### Setup

```bash
# Install WebCMD globally
npm install -g @agentrhq/webcmd

# Clone this repo
git clone https://github.com/kcfl/Slabhackathon-sitesecurityscanner.git
cd Slabhackathon-sitesecurityscanner

# Install dependencies
npm install

# Set up the WebCMD adapter used by this project
webcmd browser init scanner/scripts
# (adapter logic lives in this repo — see /webcmd-adapters if included, or set up per WebCMD docs)

# Set your Gemini API key
# PowerShell:
$env:GEMINI_API_KEY="your-api-key-here"
# cmd:
set GEMINI_API_KEY=your-api-key-here

# Run the server
node server.js
```

Then open **http://localhost:3000** in your browser.

---

## Example Result

Scanning `github.com` returned a **95/100** score, correctly identifying a real Content-Security-Policy issue (`unsafe-inline` in the `style-src` directive) with a specific, actionable fix — along with a minor finding on third-party script exposure sourced directly from the WebCMD scan.

---

## Team

Built at SLAB Hackathon 2026 by [Your Team Name].

## Credits

- [Coding Club SATI](https://www.linkedin.com/company/coding-club-sati/) — event organizers
- [WebCMD](https://github.com/agentrhq/webcmd) by Agentr, Inc.
