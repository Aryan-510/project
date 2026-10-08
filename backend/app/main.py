import json
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .config import settings
from .database import Base, engine, get_db
from .dependencies import get_admin_user, get_current_user
from .detector import predict
from .models import Scan, User
from .schemas import (
    DashboardResponse,
    LoginRequest,
    PredictionRequest,
    PredictionResponse,
    RegisterRequest,
    ScanResponse,
    TokenResponse,
    UserResponse,
)
from .security import create_access_token, hash_password, verify_password

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI Phishing Detection API",
    version="1.0.0",
    description="Backend API for the phishing detection system.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"message": "AI Phishing Detection API is running"}


@app.post("/api/auth/register", response_model=TokenResponse)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.scalar(select(User).where(User.email == payload.email))
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_count = db.scalar(select(func.count(User.id))) or 0
    user = User(
        name=payload.name,
        email=payload.email,
        password_hash=hash_password(payload.password),
        # First account becomes admin for local/demo setup.
        is_admin=(user_count == 0),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return TokenResponse(access_token=create_access_token(user.id))


@app.post("/api/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    return TokenResponse(access_token=create_access_token(user.id))


@app.get("/api/auth/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@app.post("/api/predict", response_model=PredictionResponse)
def create_prediction(
    payload: PredictionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    result = predict(payload.input_text)

    scan = Scan(
        user_id=current_user.id,
        input_text=payload.input_text,
        scan_type=payload.scan_type,
        prediction=result["prediction"],
        confidence=result["confidence"],
        risk_score=result["risk_score"],
        reasons=json.dumps(result["reasons"]),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    return PredictionResponse(
        scan_id=scan.id,
        **result,
    )


@app.get("/api/history", response_model=list[ScanResponse])
def history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scans = db.scalars(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
    ).all()

    return [
        ScanResponse(
            id=s.id,
            input_text=s.input_text,
            scan_type=s.scan_type,
            prediction=s.prediction,
            confidence=s.confidence,
            risk_score=s.risk_score,
            reasons=json.loads(s.reasons or "[]"),
            created_at=s.created_at,
        )
        for s in scans
    ]


@app.get("/api/dashboard", response_model=DashboardResponse)
def dashboard(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scans = db.scalars(
        select(Scan).where(Scan.user_id == current_user.id)
    ).all()

    total = len(scans)
    phishing = sum(s.prediction == "Phishing" for s in scans)
    safe = total - phishing
    average = round(sum(s.risk_score for s in scans) / total, 2) if total else 0.0

    return DashboardResponse(
        total_scans=total,
        phishing_scans=phishing,
        safe_scans=safe,
        average_risk=average,
    )


@app.get("/api/admin/users", response_model=list[UserResponse])
def admin_users(
    _: User = Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    return db.scalars(select(User).order_by(User.created_at.desc())).all()


@app.get("/api/admin/scans")
def admin_scans(
    _: User = Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    scans = db.scalars(select(Scan).order_by(Scan.created_at.desc())).all()
    return [
        {
            "id": s.id,
            "user_id": s.user_id,
            "email": s.user.email,
            "prediction": s.prediction,
            "risk_score": s.risk_score,
            "created_at": s.created_at,
        }
        for s in scans
    ]

