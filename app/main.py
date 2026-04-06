import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.middleware.security_headers import SecurityHeadersMiddleware
from app.routers import auth, users

# Rate limiter (shared across routers via app.state)
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="FastAPI Security Guide")

# Security headers
app.add_middleware(SecurityHeadersMiddleware)

# CORS — read origins from environment, never hardcode
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Routers
app.include_router(auth.router)
app.include_router(users.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
