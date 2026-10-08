from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    is_admin: bool
    created_at: datetime


class PredictionRequest(BaseModel):
    input_text: str = Field(min_length=1, max_length=10000)
    scan_type: str = Field(default="URL", pattern="^(URL|Email / Text)$")


class PredictionResponse(BaseModel):
    scan_id: int
    prediction: str
    confidence: float | None
    risk_score: int
    reasons: list[str]


class ScanResponse(BaseModel):
    id: int
    input_text: str
    scan_type: str
    prediction: str
    confidence: float | None
    risk_score: int
    reasons: list[str]
    created_at: datetime


class DashboardResponse(BaseModel):
    total_scans: int
    phishing_scans: int
    safe_scans: int
    average_risk: float

