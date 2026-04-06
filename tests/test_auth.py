"""Tests for authentication endpoints: register, login, refresh, logout."""
import pytest
from datetime import datetime, timedelta, timezone
import jwt
import os

from app.auth.revocation import clear as clear_revoked


@pytest.fixture(autouse=True)
def reset_revocation():
    """Clear revocation list before each test."""
    clear_revoked()
    yield
    clear_revoked()


async def test_register(client):
    response = await client.post("/auth/register", json={
        "username": "newuser",
        "password": "StrongPass123!",
    })
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newuser"
    assert "id" in data


async def test_register_duplicate_username(client):
    await client.post("/auth/register", json={"username": "dup", "password": "pass1"})
    response = await client.post("/auth/register", json={"username": "dup", "password": "pass2"})
    assert response.status_code == 400


async def test_login_success(client, registered_user):
    response = await client.post("/auth/login", data={
        "username": registered_user["username"],
        "password": registered_user["password"],
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


async def test_login_token_contains_jti(client, registered_user):
    """Access tokens must include a jti claim for revocation support."""
    response = await client.post("/auth/login", data={
        "username": registered_user["username"],
        "password": registered_user["password"],
    })
    token = response.json()["access_token"]
    payload = jwt.decode(token, options={"verify_signature": False})
    assert "jti" in payload


async def test_login_wrong_password(client, registered_user):
    response = await client.post("/auth/login", data={
        "username": registered_user["username"],
        "password": "wrongpassword",
    })
    assert response.status_code == 401


async def test_login_nonexistent_user(client):
    response = await client.post("/auth/login", data={
        "username": "ghost",
        "password": "password",
    })
    assert response.status_code == 401


async def test_refresh_token(client, registered_user):
    login_response = await client.post("/auth/login", data={
        "username": registered_user["username"],
        "password": registered_user["password"],
    })
    refresh_token = login_response.json()["refresh_token"]

    response = await client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 200
    assert "access_token" in response.json()


async def test_refresh_with_access_token_fails(client, auth_headers):
    """An access token cannot be used as a refresh token."""
    access_token = auth_headers["Authorization"].removeprefix("Bearer ")
    response = await client.post("/auth/refresh", json={"refresh_token": access_token})
    assert response.status_code == 401


async def test_refresh_with_invalid_token(client):
    response = await client.post("/auth/refresh", json={"refresh_token": "not.a.token"})
    assert response.status_code == 401


async def test_expired_token_rejected(client):
    """Expired tokens must be rejected."""
    secret = os.environ["JWT_SECRET"]
    expired_payload = {
        "sub": "user-id",
        "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
        "jti": "some-jti",
        "type": "access",
    }
    expired_token = jwt.encode(expired_payload, secret, algorithm="HS256")

    response = await client.get("/users/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401


async def test_logout_revokes_token(client, auth_headers):
    """After logout, the same access token must be rejected."""
    # Token works before logout
    response = await client.get("/users/me", headers=auth_headers)
    assert response.status_code == 200

    # Logout
    logout_response = await client.post("/auth/logout", headers=auth_headers)
    assert logout_response.status_code == 204

    # Same token is now rejected
    response = await client.get("/users/me", headers=auth_headers)
    assert response.status_code == 401


async def test_logout_requires_auth(client):
    response = await client.post("/auth/logout")
    assert response.status_code == 401
