import tkinter as tk
from tkinter import font as tkfont
import re

# ─── Phishing Detection Logic ───────────────────────────────────────────────

PHISHING_WORDS = [
    "urgent", "verify", "click here", "click now", "free", "winner",
    "congratulations", "account suspended", "confirm your", "update your",
    "limited time", "act now", "immediately", "your account", "will be blocked",
    "security alert", "unusual activity", "prize", "claim now", "expires",
    "password", "login", "sign in", "bank", "credit card", "ssn", "social security",
    "otp", "one time", "reset your", "suspended", "deactivated", "restricted"
]

PHISHING_DOMAINS = [
    "bit.ly", "tinyurl", "free-", "-free", "secure-", "-secure",
    "verify-", "-verify", "update-", "-update", "account-", "-login",
    "paypa1", "amaz0n", "g00gle", "micros0ft", "app1e"
]

def analyze_email(text):
    score = 0
    findings = []
    text_lower = text.lower()

    # Check suspicious words
    found_words = [w for w in PHISHING_WORDS if w in text_lower]
    if found_words:
        score += len(found_words) * 10
        findings.append(f"⚠  Suspicious words found: {', '.join(found_words[:5])}")

    # Check URLs
    urls = re.findall(r'https?://\S+|www\.\S+', text_lower)
    if urls:
        findings.append(f"🔗  URLs detected: {len(urls)} link(s) found")
        score += len(urls) * 15
        for domain in PHISHING_DOMAINS:
            if any(domain in url for url in urls):
                score += 30
                findings.append(f"🚨  Suspicious domain pattern: '{domain}'")
                break

    # Check fake brand spelling
    fake_brands = re.findall(r'paypa[l1]|amaz[o0]n|g[o0]{2}gle|micros[o0]ft|app[l1]e', text_lower)
    if fake_brands:
        score += 40
        findings.append(f"🚨  Fake brand name detected: {', '.join(set(fake_brands))}")

    # Check urgency patterns
    urgency = re.findall(r'\b(24 hours?|48 hours?|immediately|right now|asap|today only)\b', text_lower)
    if urgency:
        score += 20
        findings.append(f"⏰  Urgency pressure: {', '.join(set(urgency))}")

    # Check ALL CAPS words (shouting = manipulation)
    caps_words = re.findall(r'\b[A-Z]{4,}\b', text)
    if len(caps_words) > 2:
        score += 15
        findings.append(f"📢  Excessive CAPS detected: {', '.join(caps_words[:3])}")

    # Check for asking sensitive info
    sensitive = re.findall(r'\b(password|otp|pin|cvv|ssn|social security|credit card|bank account)\b', text_lower)
    if sensitive:
        score += 35
        findings.append(f"🔐  Asking for sensitive info: {', '.join(set(sensitive))}")

    # Verdict
    if score == 0:
        verdict = "SAFE"
        color = "#00e676"
        detail = "No phishing indicators found."
    elif score < 30:
        verdict = "SUSPICIOUS"
        color = "#ffca28"
        detail = "Some red flags detected. Be careful."
    elif score < 60:
        verdict = "LIKELY PHISHING"
        color = "#ff7043"
        detail = "Multiple phishing indicators found!"
    else:
        verdict = "PHISHING!"
        color = "#f44336"
        detail = "High risk! Do NOT click any links."

    return verdict, color, score, findings, detail


# ─── Tkinter UI ──────────────────────────────────────────────────────────────

class PhishingDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Email Detector")
        self.root.geometry("720x680")
        self.root.resizable(False, False)
        self.root.configure(bg="#0d1117")

        self._build_ui()

    def _build_ui(self):
        BG = "#0d1117"
        CARD = "#161b22"
        BORDER = "#30363d"
        ACCENT = "#58a6ff"
        TEXT = "#e6edf3"
        MUTED = "#8b949e"

        # Header
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=30, pady=(28, 0))

        tk.Label(header, text="🛡", font=("Segoe UI Emoji", 28),
                 bg=BG, fg=ACCENT).pack(side="left")

        title_frame = tk.Frame(header, bg=BG)
        title_frame.pack(side="left", padx=12)
        tk.Label(title_frame, text="Phishing Detector",
                 font=("Courier New", 20, "bold"), bg=BG, fg=TEXT).pack(anchor="w")
        tk.Label(title_frame, text="Paste email content below to analyze",
                 font=("Courier New", 9), bg=BG, fg=MUTED).pack(anchor="w")

        # Divider
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", padx=30, pady=16)

        # Input label
        tk.Label(self.root, text="EMAIL CONTENT",
                 font=("Courier New", 9, "bold"), bg=BG, fg=MUTED).pack(anchor="w", padx=30)

        # Text area card
        text_card = tk.Frame(self.root, bg=BORDER, bd=0)
        text_card.pack(fill="x", padx=30, pady=(6, 0))

        text_inner = tk.Frame(text_card, bg=CARD, bd=0)
        text_inner.pack(fill="both", padx=1, pady=1)

        self.text_input = tk.Text(
            text_inner,
            height=10,
            bg=CARD,
            fg=TEXT,
            insertbackground=ACCENT,
            font=("Courier New", 11),
            relief="flat",
            padx=14,
            pady=12,
            wrap="word",
            selectbackground="#264f78"
        )
        self.text_input.pack(fill="both")

        placeholder = "Paste the email text here...\n\nExample: Dear user, your account has been SUSPENDED. Click here immediately to verify: http://bit.ly/fake-link"
        self.text_input.insert("1.0", placeholder)
        self.text_input.config(fg="#555d68")

        def on_focus_in(e):
            if self.text_input.get("1.0", "end-1c") == placeholder:
                self.text_input.delete("1.0", tk.END)
                self.text_input.config(fg=TEXT)

        def on_focus_out(e):
            if not self.text_input.get("1.0", "end-1c").strip():
                self.text_input.insert("1.0", placeholder)
                self.text_input.config(fg="#555d68")

        self.text_input.bind("<FocusIn>", on_focus_in)
        self.text_input.bind("<FocusOut>", on_focus_out)

        # Buttons row
        btn_row = tk.Frame(self.root, bg=BG)
        btn_row.pack(fill="x", padx=30, pady=14)

        analyze_btn = tk.Button(
            btn_row,
            text="  ANALYZE EMAIL  ",
            font=("Courier New", 11, "bold"),
            bg=ACCENT,
            fg="#0d1117",
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=8,
            command=self.analyze
        )
        analyze_btn.pack(side="left")

        clear_btn = tk.Button(
            btn_row,
            text="  CLEAR  ",
            font=("Courier New", 11),
            bg=BORDER,
            fg=MUTED,
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=8,
            command=self.clear
        )
        clear_btn.pack(side="left", padx=(10, 0))

        # Divider
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", padx=30)

        # Result section
        result_outer = tk.Frame(self.root, bg=BG)
        result_outer.pack(fill="both", expand=True, padx=30, pady=16)

        # Verdict badge
        self.verdict_frame = tk.Frame(result_outer, bg=BG)
        self.verdict_frame.pack(fill="x", pady=(0, 10))

        self.verdict_label = tk.Label(
            self.verdict_frame,
            text="— Awaiting Analysis —",
            font=("Courier New", 15, "bold"),
            bg=BG,
            fg=MUTED
        )
        self.verdict_label.pack(side="left")

        self.score_label = tk.Label(
            self.verdict_frame,
            text="",
            font=("Courier New", 10),
            bg=BG,
            fg=MUTED
        )
        self.score_label.pack(side="right")

        # Findings box
        tk.Label(result_outer, text="ANALYSIS DETAILS",
                 font=("Courier New", 9, "bold"), bg=BG, fg=MUTED).pack(anchor="w")

        findings_card = tk.Frame(result_outer, bg=BORDER)
        findings_card.pack(fill="both", expand=True, pady=(6, 0))

        findings_inner = tk.Frame(findings_card, bg=CARD)
        findings_inner.pack(fill="both", expand=True, padx=1, pady=1)

        self.findings_text = tk.Text(
            findings_inner,
            bg=CARD,
            fg=TEXT,
            font=("Courier New", 10),
            relief="flat",
            padx=14,
            pady=12,
            state="disabled",
            wrap="word",
            height=8
        )
        self.findings_text.pack(fill="both", expand=True)

    def analyze(self):
        content = self.text_input.get("1.0", "end-1c").strip()
        if not content or content.startswith("Paste the email"):
            self.show_findings(["  Please paste an email to analyze."], "INPUT NEEDED", "#8b949e", 0, "")
            return

        verdict, color, score, findings, detail = analyze_email(content)
        self.verdict_label.config(text=f"  {verdict}", fg=color)
        self.score_label.config(text=f"Risk Score: {score}/100+", fg=color)
        self.show_findings(findings, verdict, color, score, detail)

    def show_findings(self, findings, verdict, color, score, detail):
        self.findings_text.config(state="normal")
        self.findings_text.delete("1.0", tk.END)

        if detail:
            self.findings_text.insert(tk.END, f"→  {detail}\n\n")

        if findings:
            for f in findings:
                self.findings_text.insert(tk.END, f"  {f}\n")
        else:
            self.findings_text.insert(tk.END, "  ✅  No suspicious patterns detected in this email.")

        self.findings_text.config(state="disabled")

    def clear(self):
        self.text_input.delete("1.0", tk.END)
        self.verdict_label.config(text="— Awaiting Analysis —", fg="#8b949e")
        self.score_label.config(text="")
        self.findings_text.config(state="normal")
        self.findings_text.delete("1.0", tk.END)
        self.findings_text.config(state="disabled")


# ─── Run ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingDetectorApp(root)
    root.mainloop()