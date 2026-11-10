"""Tests for risk_analyzer.py, using small hand-built transaction sets."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from risk_analyzer import analyze, load_transactions


def row(tid, **overrides):
    base = {
        "transaction_id": tid,
        "date": "2026-08-03",
        "time": "10:00",
        "vendor": "Acme",
        "amount": "100.00",
        "requester": "jdoe",
        "approver": "asmith",
        "payment_method": "ACH",
        "bank_account_last4": "1234",
        "description": "test",
        "_amount": 100.00,
        "_hour": 10,
    }
    base.update(overrides)
    return base


def rules(findings):
    return {f["rule"] for f in findings}


def test_duplicate_payment():
    rows = [row("T1", amount="450.00", _amount=450.00),
            row("T2", amount="450.00", _amount=450.00)]
    assert "Duplicate payment" in rules(analyze(rows))


def test_no_duplicate_when_amount_differs():
    rows = [row("T1", amount="450.00", _amount=450.00),
            row("T2", amount="451.00", _amount=451.00)]
    assert "Duplicate payment" not in rules(analyze(rows))


def test_split_transaction():
    rows = [row("T1", amount="6000.00", _amount=6000.00),
            row("T2", amount="5500.00", _amount=5500.00)]
    assert "Split transaction" in rules(analyze(rows))


def test_no_split_when_total_under_threshold():
    rows = [row("T1", amount="4000.00", _amount=4000.00),
            row("T2", amount="4000.00", _amount=4000.00)]
    assert "Split transaction" not in rules(analyze(rows))


def test_segregation_of_duties():
    rows = [row("T1", requester="mchen", approver="mchen")]
    assert "Segregation of duties violation" in rules(analyze(rows))


def test_vendor_bank_change():
    rows = [row("T1", bank_account_last4="1111"),
            row("T2", bank_account_last4="2222")]
    assert "Vendor bank account change" in rules(analyze(rows))


def test_after_hours_approval():
    rows = [row("T1", time="02:45", _hour=2)]
    assert "After-hours approval" in rules(analyze(rows))


def test_clean_data_has_no_high_or_medium_findings():
    rows = [row("T1"), row("T2", vendor="Other", amount="250.50", _amount=250.50)]
    severe = {f["rule"] for f in analyze(rows) if f["severity"] in ("High", "Medium")}
    assert severe == set()


def test_sample_file_finds_all_six_rules():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "samples", "transactions.csv")
    findings = analyze(load_transactions(path))
    assert rules(findings) == {
        "Duplicate payment",
        "Split transaction",
        "Segregation of duties violation",
        "Vendor bank account change",
        "After-hours approval",
        "High-value payment",
        "Round-dollar payment",
    }
    assert len(findings) == 9
