# AI Phishing Detection System — Full Stack

## Architecture

Streamlit frontend -> FastAPI -> detector -> ML model
                              |
                              -> database


## Model evaluation

The Model Evaluation page uses these included files in `models/`:

- `phishing_model.pkl`
- `phishing.csv`

The page recreates the 80/20 `train_test_split` with `random_state=42`, matching the original `train_model.py`, and reports:

- Accuracy
- Precision
- Recall
- F1-score
- ROC-AUC
- Confusion matrix
- ROC curve

This evaluation is for the full XGBoost model. The lightweight model is intentionally not evaluated here yet because its training script currently defines 9 features while the current realtime Streamlit extractor defines 14 features; that mismatch should be resolved before reporting its metrics.

