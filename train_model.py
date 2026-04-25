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
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt

cm = confusion_matrix(y_test, pred)

print("Confusion Matrix:")
print(cm)

# Plot confusion matrix
plt.figure()
plt.imshow(cm)
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")

# Add values inside matrix
for i in range(len(cm)):
    for j in range(len(cm[0])):
        plt.text(j, i, cm[i][j], ha='center', va='center')

plt.savefig("confusion_matrix.png")
accuracy = accuracy_score(y_test, pred)

print("Model Accuracy:", round(accuracy * 100, 2), "%")

# Save model
joblib.dump(model, "phishing_model.pkl")

print("Model saved successfully")
