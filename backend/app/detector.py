import os
import re
from pathlib import Path
import joblib
import numpy as np
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_DIR = BASE_DIR / "models"

TRUSTED_DOMAINS = [
    "google.com", "www.google.com", "youtube.com",
    "github.com", "microsoft.com", "wikipedia.org"
]

KEYWORDS = [
    "verify your account", "urgent", "click here",
    "reset password", "confirm now", "login immediately",
    "free reward", "verify now", "account update", "security alert"
]

SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl", ".ru", ".xyz",
    "account-update", "secure-login", "login-update"
]

LIGHT_MODEL = None
model_path = MODEL_DIR / "light_phishing_model.pkl"
if model_path.exists():
    LIGHT_MODEL = joblib.load(model_path)


def is_trusted_host(hostname):
    host = str(hostname or "").lower().strip()
    if not host:
        return False
    for domain in TRUSTED_DOMAINS:
        base = domain.lower().replace("www.", "")
        if host == base or host.endswith("." + base):
            return True
    return False


def rule_detect(text):
    text_lower = str(text).lower()
    reasons = []

    for kw in KEYWORDS:
        if kw in text_lower:
            reasons.append(f"Suspicious phrase: '{kw}'")

    for dom in SUSPICIOUS_DOMAINS:
        if dom in text_lower:
            reasons.append(f"Suspicious domain/shortener: '{dom}'")

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

    return len(reasons) > 0, reasons


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


def predict(input_text: str):
    rule_flag, reasons = rule_detect(input_text)

    ml_flag = False
    confidence = None

    if LIGHT_MODEL is not None:
        try:
            features = extract_light_features_from_url(input_text)
            expected = getattr(LIGHT_MODEL, "n_features_in_", None)

            if expected is None or features.shape[1] == expected:
                pred = int(LIGHT_MODEL.predict(features)[0])
                probs = LIGHT_MODEL.predict_proba(features)[0]
                confidence = round(float(max(probs)) * 100, 2)
                ml_flag = bool(pred)
        except Exception:
            # A malformed text input should not take down the API.
            pass

    final_flag = rule_flag or ml_flag

    base = min(len(reasons) * 20, 80)
    ml_bonus = (confidence / 100 * 20) if confidence is not None else 0
    risk_score = min(int(base + ml_bonus), 100)

    return {
        "prediction": "Phishing" if final_flag else "Safe",
        "confidence": confidence,
        "risk_score": risk_score,
        "reasons": reasons,
    }

