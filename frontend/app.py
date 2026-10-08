import os
import requests
import streamlit as st
import pandas as pd

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

st.set_page_config(
    page_title="AI Phishing Detection System",
    page_icon="🛡️",
    layout="wide",
)

st.markdown("""
<style>
.main { background: #f5f8ff; }
.block-container { max-width: 1100px; }
.card {
    padding: 1rem;
    border-radius: 14px;
    background: white;
    border: 1px solid #dbe4f5;
}
</style>
""", unsafe_allow_html=True)


def api(method, path, token=None, **kwargs):
    headers = kwargs.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.request(
        method,
        f"{API_URL}{path}",
        headers=headers,
        timeout=30,
        **kwargs,
    )


if "token" not in st.session_state:
    st.session_state.token = None
if "user" not in st.session_state:
    st.session_state.user = None


def logout():
    st.session_state.token = None
    st.session_state.user = None
    st.rerun()


if not st.session_state.token:
    st.title("🛡️ AI Phishing Detection System")
    st.caption("Secure URL and message analysis with ML + explainable rules.")

    login_tab, register_tab = st.tabs(["Login", "Create account"])

    with login_tab:
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login", type="primary"):
            r = api("POST", "/api/auth/login", json={"email": email, "password": password})
            if r.ok:
                st.session_state.token = r.json()["access_token"]
                me = api("GET", "/api/auth/me", st.session_state.token)
                st.session_state.user = me.json()
                st.rerun()
            else:
                st.error(r.json().get("detail", "Login failed"))

    with register_tab:
        name = st.text_input("Name")
        email = st.text_input("Email", key="register_email")
        password = st.text_input("Password", type="password", key="register_password")
        if st.button("Create account"):
            r = api(
                "POST",
                "/api/auth/register",
                json={"name": name, "email": email, "password": password},
            )
            if r.ok:
                st.session_state.token = r.json()["access_token"]
                me = api("GET", "/api/auth/me", st.session_state.token)
                st.session_state.user = me.json()
                st.rerun()
            else:
                st.error(r.json().get("detail", "Registration failed"))

    st.info("For this local/demo build, the first registered account becomes admin.")
    st.stop()


user = st.session_state.user

st.sidebar.title("🛡️ Threat Tools")
st.sidebar.write(f"Signed in as **{user['name']}**")
if st.sidebar.button("Logout"):
    logout()

menu_options = ["Dashboard", "Realtime Scanner", "History", "Model Evaluation"]
if user.get("is_admin"):
    menu_options.append("Admin")

menu = st.sidebar.radio("Navigation", menu_options)

if menu == "Dashboard":
    st.title("Dashboard")
    r = api("GET", "/api/dashboard", st.session_state.token)
    if not r.ok:
        st.error(r.text)
        st.stop()

    data = r.json()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Scans", data["total_scans"])
    c2.metric("Phishing", data["phishing_scans"])
    c3.metric("Safe", data["safe_scans"])
    c4.metric("Average Risk", f"{data['average_risk']}%")

elif menu == "Realtime Scanner":
    st.title("Realtime Scanner")
    mode = st.radio("Scan Type", ["URL", "Email / Text"])
    if mode == "URL":
        value = st.text_input("Enter a URL")
    else:
        value = st.text_area("Paste suspicious email/message", height=180)

    if st.button("Analyze Threat", type="primary"):
        if not value.strip():
            st.warning("Enter something to analyze.")
        else:
            r = api(
                "POST",
                "/api/predict",
                st.session_state.token,
                json={"input_text": value, "scan_type": mode},
            )
            if not r.ok:
                st.error(r.json().get("detail", r.text))
            else:
                result = r.json()
                if result["prediction"] == "Phishing":
                    st.error("⚠️ Phishing / suspicious content detected.")
                else:
                    st.success("✅ No immediate threat detected.")

                c1, c2 = st.columns(2)
                c1.metric("Risk Score", f"{result['risk_score']}%")
                c2.metric(
                    "Model Confidence",
                    f"{result['confidence']}%" if result["confidence"] is not None else "N/A",
                )

                st.progress(result["risk_score"] / 100)

                st.subheader("Detection Reasons")
                if result["reasons"]:
                    for reason in result["reasons"]:
                        st.write(f"• {reason}")
                else:
                    st.write("No heuristic flags detected.")

elif menu == "History":
    st.title("Scan History")
    r = api("GET", "/api/history", st.session_state.token)
    if not r.ok:
        st.error(r.text)
    else:
        data = r.json()
        if not data:
            st.info("No scans yet.")
        else:
            rows = []
            for s in data:
                rows.append({
                    "Date": s["created_at"],
                    "Type": s["scan_type"],
                    "Input": s["input_text"],
                    "Prediction": s["prediction"],
                    "Risk": f"{s['risk_score']}%",
                    "Confidence": (
                        f"{s['confidence']}%" if s["confidence"] is not None else "N/A"
                    ),
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True)


elif menu == "Model Evaluation":
    st.title("Model Evaluation")
    st.caption(
        "Evaluate the saved XGBoost model on the same 80/20 split used by "
        "the original training script (random_state=42)."
    )

    import joblib
    import numpy as np
    import matplotlib.pyplot as plt
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        accuracy_score,
        precision_score,
        recall_score,
        f1_score,
        roc_auc_score,
        confusion_matrix,
        ConfusionMatrixDisplay,
        roc_curve,
    )

    model_path = os.path.join("..", "models", "phishing_model.pkl")
    dataset_path = os.path.join("..", "models", "phishing.csv")

    if not os.path.exists(model_path):
        st.error("phishing_model.pkl was not found in the models folder.")
        st.stop()

    if not os.path.exists(dataset_path):
        st.warning(
            "Copy phishing.csv from your original project into the models folder "
            "to run this evaluation."
        )
        st.stop()

    try:
        model = joblib.load(model_path)
        data = pd.read_csv(dataset_path)

        X = data.iloc[:, :-1]
        y = data.iloc[:, -1]

        if set(pd.Series(y).dropna().unique()) == {-1, 1}:
            y = y.replace({-1: 0, 1: 1})

        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=0.2,
            random_state=42,
        )

        predictions = model.predict(X_test)

        if not hasattr(model, "predict_proba"):
            st.error("This saved model does not provide probability estimates.")
            st.stop()

        probabilities = model.predict_proba(X_test)[:, 1]

        accuracy = accuracy_score(y_test, predictions)
        precision = precision_score(y_test, predictions, zero_division=0)
        recall = recall_score(y_test, predictions, zero_division=0)
        f1 = f1_score(y_test, predictions, zero_division=0)
        roc_auc = roc_auc_score(y_test, probabilities)

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Accuracy", f"{accuracy * 100:.2f}%")
        c2.metric("Precision", f"{precision * 100:.2f}%")
        c3.metric("Recall", f"{recall * 100:.2f}%")
        c4.metric("F1 Score", f"{f1 * 100:.2f}%")
        c5.metric("ROC-AUC", f"{roc_auc:.4f}")

        st.subheader("Confusion Matrix")
        cm = confusion_matrix(y_test, predictions)
        fig_cm, ax_cm = plt.subplots()
        ConfusionMatrixDisplay(
            confusion_matrix=cm,
            display_labels=["Legitimate", "Phishing"],
        ).plot(ax=ax_cm)
        ax_cm.set_title("XGBoost Confusion Matrix")
        st.pyplot(fig_cm)
        plt.close(fig_cm)

        st.subheader("ROC Curve")
        fpr, tpr, _ = roc_curve(y_test, probabilities)
        fig_roc, ax_roc = plt.subplots()
        ax_roc.plot(fpr, tpr, label=f"ROC-AUC = {roc_auc:.4f}")
        ax_roc.plot([0, 1], [0, 1], linestyle="--")
        ax_roc.set_xlabel("False Positive Rate")
        ax_roc.set_ylabel("True Positive Rate")
        ax_roc.set_title("XGBoost ROC Curve")
        ax_roc.legend()
        ax_roc.grid(True, alpha=0.25)
        st.pyplot(fig_roc)
        plt.close(fig_roc)

        st.info(
            f"Evaluation uses {len(X_test)} test samples. "
            "The split follows the original training script: 80% train / 20% test, "
            "random_state=42."
        )

    except Exception as exc:
        st.error(f"Evaluation failed: {exc}")

else:
    st.title("Admin Dashboard")

    users = api("GET", "/api/admin/users", st.session_state.token)
    scans = api("GET", "/api/admin/scans", st.session_state.token)

    if users.ok:
        st.subheader("Users")
        st.dataframe(
            pd.DataFrame([
                {
                    "ID": u["id"],
                    "Name": u["name"],
                    "Email": u["email"],
                    "Admin": u["is_admin"],
                    "Created": u["created_at"],
                }
                for u in users.json()
            ]),
            use_container_width=True,
        )

    if scans.ok:
        st.subheader("All Scans")
        st.dataframe(pd.DataFrame(scans.json()), use_container_width=True)

