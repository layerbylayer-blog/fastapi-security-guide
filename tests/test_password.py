"""Unit tests for password hashing."""
from app.auth.password import hash_password, verify_password


def test_hash_is_different_from_plain():
    hashed = hash_password("mysecretpassword")
    assert hashed != "mysecretpassword"


def test_verify_correct_password():
    hashed = hash_password("correct-password")
    assert verify_password("correct-password", hashed) is True


def test_verify_wrong_password():
    hashed = hash_password("correct-password")
    assert verify_password("wrong-password", hashed) is False


def test_two_hashes_differ():
    """bcrypt is salted: same password produces different hashes."""
    h1 = hash_password("same-password")
    h2 = hash_password("same-password")
    assert h1 != h2
    # Both should still verify correctly
    assert verify_password("same-password", h1) is True
    assert verify_password("same-password", h2) is True
