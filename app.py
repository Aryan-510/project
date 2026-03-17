import streamlit as st
import re
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from datetime import datetime
import os

st.set_page_config(
    page_title="Cyber Threat and Phishing Detection System",
    layout="wide",
    page_icon=""
)

# Custom CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Source+Serif+4:wght@500;600;700&display=swap');

    :root {
        --bg: #f2f6ff;
        --surface: #ffffff;
        --surface-soft: #f8faff;
        --text: #12233f;
        --muted: #3f567a;
        --accent: #2458d6;
        --accent-strong: #1945ae;
        --danger-bg: #fff3f3;
        --danger-border: #e7a9a9;
        --danger-text: #8e1f1f;
        --success-bg: #eefaf2;
        --success-border: #9fd3b6;
        --success-text: #185b38;
        --info-bg: #edf4ff;
        --info-border: #b8cdf7;
        --info-text: #1f468e;
    }

    .stApp {
        background: radial-gradient(circle at 10% 0%, #ffffff 0%, var(--bg) 55%, #e6eeff 100%);
        color: var(--text);
        font-family: 'Manrope', sans-serif;
    }

    .block-container {
        padding-top: 2.1rem;
        padding-bottom: 2.5rem;
        max-width: 1100px;
    }

    p, label, li, span, div[data-testid="stMarkdownContainer"] {
        color: var(--text);
    }

    .main-header {
        font-family: 'Source Serif 4', serif;
        font-size: 2.7rem;
        color: var(--text);
        margin-bottom: 0.45rem;
        letter-spacing: -0.01em;
        line-height: 1.15;
    }

    .sub-header {
        font-size: 1.14rem;
        color: var(--muted);
        margin-bottom: 1.15rem;
        line-height: 1.6;
        font-weight: 500;
    }

    .section-title {
        font-family: 'Source Serif 4', serif;
        font-size: 1.9rem;
        color: var(--text);
        margin-top: 0.15rem;
        margin-bottom: 0.95rem;
        line-height: 1.2;
    }

    .feature-card {
        background: #ffffff;
        border: 1px solid #cfdbf5;
        border-radius: 14px;
        padding: 1.2rem 1.05rem;
        min-height: 150px;
        box-shadow: 0 16px 36px rgba(25, 58, 128, 0.11);
    }

    .feature-title {
        font-size: 1.12rem;
        font-weight: 700;
        color: var(--text);
        margin-bottom: 0.45rem;
    }

    .feature-text {
        font-size: 1rem;
        color: var(--muted);
        line-height: 1.58;
        font-weight: 500;
    }

    .success-box,
    .error-box,
    .info-box {
        padding: 0.95rem 1rem;
        border-radius: 10px;
        margin: 0.8rem 0;
        font-size: 1rem;
        font-weight: 600;
    }

    .success-box {
        background-color: var(--success-bg);
        border: 1px solid var(--success-border);
        color: var(--success-text);
    }

    .error-box {
        background-color: var(--danger-bg);
        border: 1px solid var(--danger-border);
        color: var(--danger-text);
    }

    .info-box {
        background-color: var(--info-bg);
        border: 1px solid var(--info-border);
        color: var(--info-text);
    }

    .stButton > button {
        background-color: var(--accent);
        color: #ffffff;
        border: none;
        border-radius: 9px;
        padding: 0.62rem 1.2rem;
        font-weight: 700;
        letter-spacing: 0.01em;
        font-size: 0.98rem;
        transition: all 0.18s ease;
    }

    .stButton > button:hover {
        background-color: var(--accent-strong);
        transform: translateY(-1px);
    }

    .stTextInput > div > div > input,
    .stTextArea textarea,
    .stSelectbox > div > div {
        border-radius: 10px !important;
        border: 1px solid #c9d8f7 !important;
        background-color: #ffffff !important;
        color: #12233f !important;
        font-size: 1rem !important;
    }

    .stSidebar {
        background: linear-gradient(180deg, #eaf1ff 0%, #dde8ff 100%);
        border-right: 1px solid #bfd1f3;
    }

    .stSidebar .stMarkdown h1,
    .stSidebar .stMarkdown h2,
    .stSidebar .stMarkdown h3,
    .stSidebar label,
    .stSidebar p,
    .stSidebar div {
        color: #17305f !important;
        font-weight: 600;
    }

    .stRadio label, .stSelectbox label, .stTextInput label, .stTextArea label, .stFileUploader label {
        color: #16305f !important;
        font-weight: 700 !important;
    }

    .stProgress > div > div > div > div {
        background-color: var(--accent);
    }

    .risk-level {
        display: inline-block;
        margin-top: 0.35rem;
        margin-bottom: 0.3rem;
        padding: 0.38rem 0.62rem;
        border-radius: 8px;
        font-size: 0.88rem;
        font-weight: 700;
        letter-spacing: 0.01em;
    }

    .risk-high {
        background: #fff1f1;
        border: 1px solid #f0b8b8;
        color: #9a1f1f;
    }

    .risk-low {
        background: #eefaf4;
        border: 1px solid #b7dfca;
        color: #1d6a45;
    }

    .footnote {
        color: #4e5f82;
        font-size: 0.9rem;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- trusted domains -----------------
trusted_domains = [
    "google.com",
    "www.google.com",
    "youtube.com",
    "github.com",
    "microsoft.com",
    "wikipedia.org"
]

# ----------------- helpers / detection rules -----------------
KEYWORDS = [
    "verify your account", "urgent", "click here",
    "reset password", "confirm now", "login immediately",
    "free reward", "verify now", "account update", "security alert"
]

SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl", ".ru", ".xyz",
    "account-update", "secure-login", "login-update"
]

def is_trusted_host(hostname):
    host = str(hostname or "").lower().strip()
    if not host:
        return False
    for domain in trusted_domains:
        base = domain.lower().replace("www.", "")
        if host == base or host.endswith("." + base):
            return True
    return False


def rule_detect(text):

    text_lower = str(text).lower()

    reasons = []

    # keyword checks
    for kw in KEYWORDS:
        if kw in text_lower:
            reasons.append(f"Suspicious phrase: '{kw}'")

    # suspicious domain checks
    for dom in SUSPICIOUS_DOMAINS:
        if dom in text_lower:
            reasons.append(f"Suspicious domain/shortener: '{dom}'")

    # URLs in text
    urls = re.findall(r"https?://\S+", text_lower)

    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
            reasons.append("IP-based URL detected")

        if len(url) > 70:
            reasons.append("Very long URL")

        if "@" in url:
            reasons.append("Suspicious '@' in URL")

        if url.startswith("http://"):
            reasons.append("Unsecured HTTP link")

        if url.count(".") > 3:
            reasons.append("Many subdomains (suspicious)")

        if host and not is_trusted_host(host):
            if any(dom in host for dom in [".ru", ".xyz", ".tk", ".ml"]):
                reasons.append("Suspicious TLD in hostname")

    if len(text_lower) > 500 and len(urls) == 0:
        reasons.append("Very long message without links")

    return (len(reasons) > 0), reasons


# ----------------- lightweight feature extractor -----------------
def extract_light_features_from_url(raw):

    s = str(raw)
    parsed = urlparse(s)
    domain = parsed.netloc.lower()
    url = s.lower()

    return np.array([[
        len(url),
        url.count("."),
        int(url.startswith("https")),
        int("@" in url),
        int("-" in domain),
        int(domain.replace("www.", "").isdigit()),
        len(domain),
        int(any(x in url for x in ["login", "verify", "secure", "account", "update"])),
        int(any(x in url for x in ["bit.ly", "tinyurl", "goo.gl"])),
        int("." in domain and domain.split(".")[-1] in ["ru", "xyz", "tk", "ml"]),
        int(len(domain) > 20),
        int(url.count("/") > 3),
        int("?" in url),
        int("#" in url)
    ]])


# ----------------- load models -----------------
FULL_MODEL = None
LIGHT_MODEL = None
FULL_MODEL_FEATURE_COUNT = None
LIGHT_MODEL_FEATURE_COUNT = None

if os.path.exists("phishing_model.pkl"):
    FULL_MODEL = joblib.load("phishing_model.pkl")
    FULL_MODEL_FEATURE_COUNT = getattr(FULL_MODEL, "n_features_in_", None)

if os.path.exists("light_phishing_model.pkl"):
    LIGHT_MODEL = joblib.load("light_phishing_model.pkl")
    LIGHT_MODEL_FEATURE_COUNT = getattr(LIGHT_MODEL, "n_features_in_", None)


# ----------------- UI -----------------
st.sidebar.title("Cyber Threat Tools")
st.sidebar.markdown("---")

menu = st.sidebar.selectbox(
    "Navigation",
    ["Home", "Realtime Scanner", "Batch / Offline ML", "About"]
)

if menu == "Home":
    st.markdown('<h1 class="main-header">Cyber Threat and Phishing Detection System</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">A practical security workspace that combines rule checks and machine learning to review suspicious content quickly.</p>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(
            '<div class="feature-card"><div class="feature-title">Realtime Scanning</div><div class="feature-text">Inspect emails, messages, or links in seconds and get a structured risk signal with reasons.</div></div>',
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            '<div class="feature-card"><div class="feature-title">Hybrid Detection</div><div class="feature-text">Blend transparent rule-based checks with model confidence to reduce obvious misses.</div></div>',
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            '<div class="feature-card"><div class="feature-title">Batch Evaluation</div><div class="feature-text">Upload labeled CSV data to evaluate model behavior on larger offline sets.</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.markdown('<div class="info-box">Choose a section from the sidebar to begin.</div>', unsafe_allow_html=True)

elif menu == "Realtime Scanner":

    st.markdown('<h2 class="section-title">Realtime Scanner</h2>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Submit text or a URL to estimate phishing risk and review why it was flagged.</p>', unsafe_allow_html=True)

    col1, col2 = st.columns([1, 2])
    with col1:
        mode = st.radio("Scan Type", ["Email / Text", "URL"], horizontal=False)
    with col2:
        if mode == "Email / Text":
            user_input = st.text_area("Paste suspicious message content", height=150)
        else:
            user_input = st.text_input("Paste suspicious URL")

    analyze = st.button("Analyze Threat", type="primary")

    if analyze:

        if user_input.strip() == "":
            st.warning("Please enter some text or a URL to analyze.")
        else:

            rule_flag, rule_reasons = rule_detect(user_input)

            # ML prediction
            ml_flag = False
            ml_info = None

            if LIGHT_MODEL is not None:

                feat = extract_light_features_from_url(user_input)

                if LIGHT_MODEL_FEATURE_COUNT is None or feat.shape[1] == LIGHT_MODEL_FEATURE_COUNT:

                    ml_pred = LIGHT_MODEL.predict(feat)[0]

                    probs = LIGHT_MODEL.predict_proba(feat)[0]
                    confidence = round(float(max(probs)) * 100, 2)

                    ml_flag = bool(int(ml_pred))

                    ml_info = {
                        "pred": int(ml_pred),
                        "conf": confidence
                    }

            final_flag = rule_flag or ml_flag

            base = min(len(rule_reasons) * 20, 80)

            ml_bonus = 0
            if ml_info:
                ml_bonus = ml_info["conf"] / 100 * 20

            risk_score = min(int(base + ml_bonus), 100)

            # ---------------- result ----------------
            st.markdown("### Threat Analysis Result")

            if final_flag:
                st.markdown('<div class="error-box"><strong>Threat detected.</strong> The content appears suspicious and should be treated with caution.</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="success-box"><strong>No immediate threat detected.</strong> The content appears low risk based on current checks.</div>', unsafe_allow_html=True)

            st.write(f"**Risk Score:** {risk_score}%")
            if risk_score > 0:
                st.markdown('<div class="risk-level risk-high">Threat Level: Elevated</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="risk-level risk-low">Threat Level: Safe</div>', unsafe_allow_html=True)
            st.progress(risk_score / 100)

            st.markdown("**Detection Reasons (Rules):**")

            if rule_reasons:
                for r in rule_reasons:
                    st.write("-", r)
            else:
                st.write("No heuristic flags detected.")

            if ml_info:
                st.markdown("**Model Prediction:**")
                st.write(f"**Prediction:** {'Phishing' if ml_info['pred'] == 1 else 'Safe'}")
                st.write(f"**Confidence:** {ml_info['conf']}%")


# ----------------- OFFLINE ML -----------------
elif menu == "Batch / Offline ML":

    st.markdown('<h2 class="section-title">Batch / Offline ML Evaluation</h2>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Upload a labeled CSV file to measure model performance on offline data.</p>', unsafe_allow_html=True)

    uploaded = st.file_uploader("Upload dataset CSV", type="csv")

    if uploaded is not None:

        df = pd.read_csv(uploaded)
        st.write("**Dataset Preview:**")
        st.dataframe(df.head(), use_container_width=True)

        if FULL_MODEL:

            X = df.iloc[:, :-1]
            y = df.iloc[:, -1]

            preds = FULL_MODEL.predict(X)

            acc = (preds == y.values).mean() * 100

            st.markdown('<div class="success-box"><strong>Model Accuracy:</strong> {:.2f}%</div>'.format(acc), unsafe_allow_html=True)


# ----------------- ABOUT -----------------
else:

    st.markdown('<h2 class="section-title">About This Platform</h2>', unsafe_allow_html=True)

    st.write("""
**Cyber Threat and Phishing Detection System** helps analysts and students screen potentially malicious content with fast, explainable checks.

### Key Features
- Realtime phishing checks for text and URLs
- Combined heuristic and machine learning analysis
- Offline dataset evaluation for model validation
- Risk scoring with transparent rationale

### How It Works
The system applies rule-based checks to identify known suspicious patterns, then combines that signal with model confidence from lightweight ML features to estimate overall risk.

### Technology Stack
- Frontend: Streamlit
- ML Models: XGBoost, Scikit-learn
- Data Processing: Pandas, NumPy
""")

st.markdown("---")
st.markdown('<p class="footnote">Cyber Threat and Phishing Detection System - Built with Streamlit</p>', unsafe_allow_html=True)
