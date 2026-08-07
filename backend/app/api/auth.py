from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import create_token, current_analyst, hash_password, verify_password
from ..db import execute, fetch_one
from ..models import LoginRequest, RegisterRequest, TokenResponse

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(body: RegisterRequest) -> TokenResponse:
    existing = await fetch_one("SELECT id FROM analyst WHERE email = %s", (body.email,))
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    await execute(
        "INSERT INTO analyst (email, display_name, password_hash) VALUES (%s, %s, %s)",
        (body.email, body.display_name, hash_password(body.password)),
    )
    row = await fetch_one(
        "SELECT id, role FROM analyst WHERE email = %s", (body.email,)
    )
    token = create_token(str(row["id"]), body.email, body.display_name, row["role"])
    return TokenResponse(
        access_token=token,
        analyst_id=str(row["id"]),
        email=body.email,
        display_name=body.display_name,
        role=row["role"],
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest) -> TokenResponse:
    row = await fetch_one(
        "SELECT id, display_name, password_hash, role FROM analyst WHERE email = %s",
        (body.email,),
    )
    if row is None or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    await execute(
        "UPDATE analyst SET last_login = now() WHERE id = %s", (str(row["id"]),)
    )
    token = create_token(str(row["id"]), body.email, row["display_name"], row["role"])
    return TokenResponse(
        access_token=token,
        analyst_id=str(row["id"]),
        email=body.email,
        display_name=row["display_name"],
        role=row["role"],
    )


@router.get("/me")
async def me(analyst: dict = Depends(current_analyst)) -> dict:
    return {
        "analyst_id": analyst["sub"],
        "email": analyst["email"],
        "display_name": analyst["display_name"],
        "role": analyst["role"],
    }
