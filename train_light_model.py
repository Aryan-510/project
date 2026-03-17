import argparse
import os
import sys
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
from urllib.parse import urlparse

def extract_light_features(url):
    s = str(url)
    parsed = urlparse(s)
    domain = parsed.netloc.lower()
    u = s.lower()
    return [
        len(u),
        u.count("."),
        int(u.startswith("https")),
        int("@" in u),
        int("-" in domain),
        int(domain.replace("www.","").isdigit()),
        len(domain),
        int(any(x in u for x in ["login","verify","secure","account","update"])),
        int(any(x in u for x in ["bit.ly","tinyurl","goo.gl"]))
    ]

parser = argparse.ArgumentParser(description="Train lightweight phishing model from raw URL data.")
parser.add_argument(
    "--data",
    default="phishing_raw.csv",
    help="CSV file containing at least 'url' and 'label' columns (default: phishing_raw.csv)",
)
args = parser.parse_args()

if not os.path.exists(args.data):
    print(
        f"Error: '{args.data}' not found.\n"
        "Provide a raw URL dataset with columns: url,label\n"
        "Example: python train_light_model.py --data your_urls.csv"
    )
    sys.exit(1)

df = pd.read_csv(args.data)

required_cols = {"url", "label"}
missing = required_cols - set(df.columns)
if missing:
    print(
        f"Error: Missing required columns in '{args.data}': {sorted(missing)}\n"
        f"Found columns: {list(df.columns)}"
    )
    sys.exit(1)

X = []
y = []
for _, row in df.iterrows():
    X.append(extract_light_features(row["url"]))
    y.append(int(row["label"]))

y = pd.Series(y).replace({-1: 0, 1: 1}).tolist()

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
clf = DecisionTreeClassifier()
clf.fit(X_train, y_train)
pred = clf.predict(X_test)
acc = accuracy_score(y_test, pred) * 100
print("Light model accuracy:", round(acc,2), "%")
joblib.dump(clf, "light_phishing_model.pkl")
print("Saved light_phishing_model.pkl")
