# ⚡ AI Firewall — Jailbreak Detection System

A security tool that protects Large Language Model (LLM) applications from prompt injection and jailbreak attempts. Built to demonstrate how a layered detection system can classify and log malicious prompts in real time.

---

## 🔍 What It Does

AI applications are vulnerable to jailbreak attacks — carefully crafted prompts designed to bypass safety guidelines and extract harmful outputs. This tool acts as a firewall layer that intercepts and analyses prompts before they reach your LLM.

Every prompt is assessed across two detection layers and assigned a threat level:

| Risk Level | Meaning |
|------------|---------|
| 🔴 HIGH | Clear jailbreak attempt — block immediately |
| 🟡 MEDIUM | Suspicious framing — flag for review |
| 🟢 LOW | Clean prompt — safe to process |

---

## 🛡️ Detection Architecture

### Layer 1 — Keyword & Pattern Matching
Fast regex-based scan across four attack categories:
- **Persona hijacking** — "act as", "you are DAN", "pretend you have no restrictions"
- **Restriction bypass** — "ignore your training", "no rules", "override"
- **Authority claims** — "I am a developer", "admin mode", "system prompt"
- **Harmful intent** — "how to hack", "make malware", "exploit vulnerability"

### Layer 2 — Claude API Classification
Each prompt is sent to Claude for deep semantic analysis. The model returns:
- A verdict (CLEAN / SUSPICIOUS / JAILBREAK)
- A confidence level (LOW / MEDIUM / HIGH)
- A one-sentence reason explaining the classification

### Risk Scoring
Both layers combine into a final risk score. A single jailbreak verdict or 3+ keyword hits triggers HIGH risk.

---

## 🖥️ Web Interface

- Submit any prompt for real-time analysis
- View instant verdict with colour-coded risk badge
- See which attack patterns were matched
- Live detection statistics dashboard

---

## 🚀 Running Locally

**Requirements:** Python 3.x, Anthropic API key

```bash
# Clone the repo
git clone git@github.com:LeightonSec/ai-firewall.git
cd ai-firewall

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Add your API key
echo "ANTHROPIC_API_KEY=your-key-here" > .env

# Run the server
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

---

## 📁 Project Structure

ai-firewall/
├── app.py          # Flask web server & API routes
├── detector.py     # Core detection logic (keyword + API scan)
├── logger.py       # JSON logging & statistics
├── templates/
│   └── index.html  # Web interface & dashboard
├── requirements.txt
└── .env            # API key (never committed)

---

## ⚠️ Security Notes

- API key stored in `.env` — never committed to version control
- Server bound to `127.0.0.1` — not exposed to external networks
- Input validation on all prompt submissions
- All detections logged with timestamp for audit trail

---

## 🗺️ Roadmap

- [ ] SQLite database for persistent logging
- [ ] Rate limiting to prevent API abuse
- [ ] Authentication layer for the web interface
- [ ] Docker containerisation
- [ ] Cloud deployment

---

## 👤 Author

**Leighton Wilson** — IT Deployment Engineer transitioning into Cybersecurity  
[LeightonSec GitHub](https://github.com/LeightonSec)

---

*Built as part of a hands-on cybersecurity portfolio. Feedback welcome.*