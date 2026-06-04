# 🛡️ Phishing Email Detector

A beginner-friendly cybersecurity tool built with Python that analyzes email content and detects phishing attempts using pattern matching and keyword analysis.

---

## 📌 About The Project

Phishing emails are one of the most common cyber attacks today — especially in India where millions of people receive fake OTP, bank, and prize scam emails daily.

This tool helps users **paste any suspicious email** and instantly get a risk analysis with a verdict:

- ✅ **SAFE** — No threats detected
- ⚠️ **SUSPICIOUS** — Some red flags found
- 🟠 **LIKELY PHISHING** — Multiple indicators detected
- 🔴 **PHISHING!** — High risk, do not interact

---

## 🖥️ Screenshot

> Run the tool and paste any email content to see the analysis.

---

## 🔍 Features

- Detects **suspicious keywords** — urgent, verify, click now, winner, etc.
- Flags **fake URLs** — bit.ly, tinyurl, free- domains
- Identifies **fake brand names** — Paypa1, Amaz0n, G00gle, Micros0ft
- Catches **urgency pressure** — "24 hours", "immediately", "act now"
- Warns about **sensitive info requests** — OTP, password, CVV, SSN
- Detects **excessive CAPS** — manipulation tactic
- Shows a **Risk Score** for each email
- Clean dark-themed **Tkinter GUI**

---

## 🛠️ Built With

- **Python 3** — Core language
- **Tkinter** — GUI (built-in, no install needed)
- **re (Regex)** — Pattern matching (built-in)

> ✅ No external libraries required!

---

## ▶️ How To Run

### Step 1 — Make sure Python is installed
```bash
python --version
```
If not installed, download from [python.org](https://www.python.org/downloads/)

### Step 2 — Clone this repository
```bash
git clone https://github.com/your-username/phishing-email-detector.git
cd phishing-email-detector
```

### Step 3 — Run the tool
```bash
python phishing_detector.py
```

That's it! No pip install needed. 🎉

---

## 🧪 Test It Yourself

Paste this sample phishing email in the tool to see it in action:

```
Dear user, your account has been SUSPENDED.
Click here immediately to verify your password:
http://bit.ly/amaz0n-login
Act now or your account will be blocked in 24 hours!
Enter your OTP and credit card details to restore access.
```

**Expected Result:** 🔴 PHISHING! with high risk score

---

## 📁 Project Structure

```
phishing-email-detector/
│
├── phishing_detector.py    # Main application (UI + logic)
└── README.md               # Project documentation
```

---

## 🧠 How It Works

1. User pastes email content into the text box
2. Tool runs the text through multiple checks using **Regex** and **keyword lists**
3. Each matched pattern adds to the **Risk Score**
4. Based on score, a **verdict** is displayed with detailed findings

---

## 🔒 Disclaimer

This tool is built for **educational purposes only** as a fresher cybersecurity project.
It uses rule-based detection and is **not a replacement** for professional anti-phishing software.
Always use trusted email clients with built-in spam filters for real protection.

---

## 👨‍💻 Author

**Your Name**
- GitHub: [@your-username](https://github.com/your-username)
- Made as a Fresher Cybersecurity Project

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
