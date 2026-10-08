# AI Phishing Detection System — Full Stack

This version keeps the existing phishing detection logic but adds:

- FastAPI backend
- JWT authentication
- User signup/login
- PostgreSQL-ready database layer
- Scan history
- User dashboard
- Admin dashboard
- Existing lightweight ML model integration
- Streamlit frontend

## Architecture

Streamlit frontend -> FastAPI -> detector -> ML model
                              |
                              -> database

## 1. Model files

The `models/` directory includes `light_phishing_model.pkl` for realtime predictions, plus `phishing_model.pkl` and `phishing.csv` for the Model Evaluation page.

## 2. Backend setup

Open a terminal in `backend/`:

```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload
```

API:
http://127.0.0.1:8000

Interactive API documentation:
http://127.0.0.1:8000/docs

## 3. Database

The default `.env.example` uses SQLite so the application can run without installing PostgreSQL.

For PostgreSQL, install PostgreSQL locally and create a database named `phishing_db`.

Then install the PostgreSQL driver:

```cmd
pip install psycopg[binary]
```

Set:

```env
DATABASE_URL=postgresql+psycopg://postgres:YOUR_PASSWORD@localhost:5432/phishing_db
```

Restart FastAPI.

## 4. Frontend

Open another terminal in `frontend/`:

```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Open:
http://localhost:8501

## 5. First account

For this local/demo implementation, the first registered account is automatically an admin.

For a production deployment, replace this with a controlled admin provisioning process.

## API endpoints

### Authentication
- POST `/api/auth/register`
- POST `/api/auth/login`
- GET `/api/auth/me`

### Detection
- POST `/api/predict`

### User
- GET `/api/history`
- GET `/api/dashboard`

### Admin
- GET `/api/admin/users`
- GET `/api/admin/scans`

## Important

This is a learning/demo architecture. Before production deployment, add:

- Strong secret management
- HTTPS
- Refresh tokens
- Rate limiting
- CSRF strategy if cookies are introduced
- Database migrations (Alembic)
- More robust URL validation
- Audit logging
- Proper admin provisioning
- Security review


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

