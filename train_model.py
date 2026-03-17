import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load dataset
data = pd.read_csv("phishing.csv")

# Features = all columns except last
X = data.iloc[:, :-1]

# Label = last column
y = data.iloc[:, -1]

# XGBoost expects classes like 0/1 for binary classification.
# Many phishing datasets use -1/1, so normalize when needed.
if set(pd.Series(y).dropna().unique()) == {-1, 1}:
    y = y.replace({-1: 0, 1: 1})

# Train test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = XGBClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Accuracy
pred = model.predict(X_test)
accuracy = accuracy_score(y_test, pred)

print("Model Accuracy:", round(accuracy * 100, 2), "%")

# Save model
joblib.dump(model, "phishing_model.pkl")

print("Model saved successfully")
