# fastapi-security-guide

Codice di riferimento per l'articolo [API Security in FastAPI: JWT, Rate Limiting e CORS](https://layerbylayer.dev/blog/fastapi-security-guide) su [LayerByLayer.dev](https://layerbylayer.dev).

## Struttura

```
app/
├── main.py
├── config.py               # Settings da env con pydantic-settings
├── database.py             # Engine, Base, get_db
├── models.py               # User model
├── auth/
│   ├── jwt.py              # create/decode token (PyJWT)
│   ├── password.py         # hash/verify (passlib + bcrypt)
│   └── dependencies.py     # get_current_user, get_current_active_user
├── middleware/
│   └── security_headers.py
├── repositories/
│   └── user_repository.py
├── services/
│   └── user_service.py
└── routers/
    ├── auth.py             # /auth/login, /auth/refresh, /auth/register
    └── users.py            # /users/me

tests/
├── conftest.py
├── test_auth.py
├── test_users.py
├── test_security_headers.py
└── test_password.py
```

## Quickstart

```bash
git clone https://github.com/layerbylayer-blog/fastapi-security-guide
cd fastapi-security-guide

cp .env.example .env
# Edit .env: set JWT_SECRET to a real random value

pip install -r requirements-dev.txt
pytest -v
```

## Genera un JWT_SECRET

```bash
python -c "import secrets; print(secrets.token_hex(32))"
# oppure
openssl rand -hex 32
```
