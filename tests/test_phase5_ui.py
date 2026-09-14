"""
Phase 5 - UI Data Correctness
Tests for UI formatters and logic.
"""
import pytest
from app import format_inr, _LIVE_SQL, get_db

def test_format_inr():
    assert format_inr(0) == "0"
    assert format_inr(50) == "50"
    assert format_inr(100) == "100"
    assert format_inr(1000) == "1,000"
    assert format_inr(10000) == "10,000"
    assert format_inr(100000) == "1,00,000"
    assert format_inr(1000000) == "10,00,000"
    assert format_inr(10000000) == "1,00,00,000"
    
    assert format_inr(-100000) == "-1,00,000"
    
    assert format_inr("50000") == "50,000"
    assert format_inr(None) == "None"
    assert format_inr("not-a-num") == "not-a-num"

def test_live_sql_consistency(app_client):
    # Verify that _LIVE_SQL string has the company_id check
    assert "EXISTS (SELECT 1 FROM companies" in _LIVE_SQL
    assert "c.is_approved=1" in _LIVE_SQL
    assert "c.is_active=1" in _LIVE_SQL
