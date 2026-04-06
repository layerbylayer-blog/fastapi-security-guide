"""Tests for protected user endpoints."""


async def test_get_profile_authenticated(client, auth_headers, registered_user):
    response = await client.get("/users/me", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["username"] == registered_user["username"]


async def test_get_profile_unauthenticated(client):
    response = await client.get("/users/me")
    assert response.status_code == 401


async def test_get_profile_invalid_token(client):
    response = await client.get(
        "/users/me",
        headers={"Authorization": "Bearer invalid.token.here"},
    )
    assert response.status_code == 401


async def test_get_profile_missing_bearer_prefix(client, auth_headers, registered_user):
    token = auth_headers["Authorization"].removeprefix("Bearer ")
    response = await client.get("/users/me", headers={"Authorization": token})
    assert response.status_code == 401
