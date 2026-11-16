"""Test user authentication persistence and profile management."""

import pytest
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from database.db import init_db, create_or_update_user, get_user_by_email


def test_user_creation_and_retrieval(tmp_path):
    test_db = str(tmp_path / "test_auth.db")
    init_db(test_db)

    # Test Google OAuth user profile creation
    g_user = create_or_update_user(
        email="analyst.test@gmail.com",
        name="Alex Test",
        provider="google",
        agency="State Cyber Unit",
        clearance_level="L3 Lead Forensic Specialist",
        avatar_url="https://example.com/avatar.png",
        db_path=test_db
    )
    assert g_user["email"] == "analyst.test@gmail.com"
    assert g_user["provider"] == "google"
    assert g_user["name"] == "Alex Test"
    assert g_user["clearance_level"] == "L3 Lead Forensic Specialist"

    # Test retrieval
    fetched = get_user_by_email("analyst.test@gmail.com", db_path=test_db)
    assert fetched is not None
    assert fetched["name"] == "Alex Test"

    # Test update existing user
    updated = create_or_update_user(
        email="analyst.test@gmail.com",
        name="Alex Test Updated",
        provider="google",
        agency="State Cyber Unit",
        clearance_level="L3 Lead Forensic Specialist",
        db_path=test_db
    )
    assert updated["name"] == "Alex Test Updated"
