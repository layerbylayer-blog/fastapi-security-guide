"""Verify security headers are present on all responses."""


async def test_security_headers_present(client):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-XSS-Protection") == "1; mode=block"


async def test_security_headers_on_auth_endpoints(client):
    response = await client.post("/auth/login", data={"username": "x", "password": "x"})
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
