#!/usr/bin/env python3
"""Risk and audit analyzer for transaction data.

Reads a CSV of transactions and flags patterns an auditor or risk
specialist would actually look for: duplicate payments, split
transactions that dodge an approval threshold, segregation-of-duties
violations, vendor bank-account changes, after-hours approvals, and
unusually round or high-value payments.

The output is a severity-ranked Markdown findings report plus a
machine-readable JSON file, so the results can be reviewed, tracked,
and followed up like a real audit workpaper.

Input CSV columns:
    transaction_id, date, time, vendor, amount, requester, approver,
    payment_method, bank_account_last4, description

Usage:
    python3 risk_analyzer.py --input samples/transactions.csv
    python3 risk_analyzer.py --input data.csv --report report.md --json findings.json
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime

APPROVAL_THRESHOLD = 10000.00
HIGH_VALUE_THRESHOLD = 25000.00
BUSINESS_HOURS = (8, 18)  # approvals expected between 08:00 and 18:00


def parse_amount(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def parse_hour(value):
    try:
        return int(value.split(":")[0])
    except (AttributeError, IndexError, ValueError):
        return None


def load_transactions(path):
    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        row["_amount"] = parse_amount(row.get("amount"))
        row["_hour"] = parse_hour(row.get("time", ""))
    return rows


def find_duplicates(rows):
    """Same vendor, same amount, same date, different transaction IDs."""
    seen = {}
    findings = []
    for row in rows:
        key = (row.get("vendor", ""), row.get("amount", ""), row.get("date", ""))
        if key in seen:
            findings.append({
                "rule": "Duplicate payment",
                "severity": "High",
                "transaction_id": row.get("transaction_id", ""),
                "detail": (
                    "Same vendor, amount, and date as transaction "
                    f"{seen[key]}. Possible duplicate payment."
                ),
            })
        else:
            seen[key] = row.get("transaction_id", "")
    return findings


def find_split_transactions(rows):
    """Several payments to one vendor on one day that together pass the
    approval threshold, while each payment alone stays under it."""
    groups = defaultdict(list)
    for row in rows:
        groups[(row.get("vendor", ""), row.get("requester", ""), row.get("date", ""))].append(row)
    findings = []
    for (vendor, requester, date), group in groups.items():
        if len(group) < 2:
            continue
        total = sum(r["_amount"] for r in group)
        if total >= APPROVAL_THRESHOLD and all(r["_amount"] < APPROVAL_THRESHOLD for r in group):
            ids = ", ".join(r.get("transaction_id", "") for r in group)
            findings.append({
                "rule": "Split transaction",
                "severity": "High",
                "transaction_id": ids,
                "detail": (
                    f"{len(group)} payments to {vendor} by {requester} on {date} "
                    f"total ${total:,.2f}, each under the ${APPROVAL_THRESHOLD:,.0f} "
                    "approval threshold. Possible threshold avoidance."
                ),
            })
    return findings


def find_segregation_of_duties(rows):
    findings = []
    for row in rows:
        if row.get("requester") and row.get("requester") == row.get("approver"):
            findings.append({
                "rule": "Segregation of duties violation",
                "severity": "High",
                "transaction_id": row.get("transaction_id", ""),
                "detail": (
                    f"Requester and approver are both {row.get('requester')}. "
                    "No independent approval."
                ),
            })
    return findings


def find_vendor_bank_changes(rows):
    first_account = {}
    findings = []
    for row in rows:
        vendor = row.get("vendor", "")
        account = row.get("bank_account_last4", "")
        if vendor not in first_account:
            first_account[vendor] = account
        elif account and account != first_account[vendor]:
            findings.append({
                "rule": "Vendor bank account change",
                "severity": "Medium",
                "transaction_id": row.get("transaction_id", ""),
                "detail": (
                    f"{vendor} was previously paid to an account ending in "
                    f"{first_account[vendor]} and is now paid to an account "
                    f"ending in {account}. Verify the change was authorized."
                ),
            })
    return findings


def find_after_hours_approvals(rows):
    findings = []
    for row in rows:
        hour = row["_hour"]
        if hour is not None and (hour < BUSINESS_HOURS[0] or hour >= BUSINESS_HOURS[1]):
            findings.append({
                "rule": "After-hours approval",
                "severity": "Medium",
                "transaction_id": row.get("transaction_id", ""),
                "detail": (
                    f"Approved at {row.get('time', '')}, outside normal business "
                    "hours (08:00-18:00). Worth a second look, not proof of fraud."
                ),
            })
    return findings


def find_high_value_and_round_dollar(rows):
    findings = []
    for row in rows:
        amount = row["_amount"]
        if amount >= HIGH_VALUE_THRESHOLD:
            findings.append({
                "rule": "High-value payment",
                "severity": "Medium",
                "transaction_id": row.get("transaction_id", ""),
                "detail": f"Single payment of ${amount:,.2f} exceeds the ${HIGH_VALUE_THRESHOLD:,.0f} review threshold.",
            })
        elif amount >= 1000 and amount % 1000 == 0:
            findings.append({
                "rule": "Round-dollar payment",
                "severity": "Low",
                "transaction_id": row.get("transaction_id", ""),
                "detail": (
                    f"Payment of ${amount:,.2f} is an exact round amount. "
                    "A weak indicator on its own; useful combined with other flags."
                ),
            })
    return findings


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

ALL_RULES = (
    find_duplicates,
    find_split_transactions,
    find_segregation_of_duties,
    find_vendor_bank_changes,
    find_after_hours_approvals,
    find_high_value_and_round_dollar,
)


def analyze(rows):
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(rows))
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return findings


def render_report(findings, total_transactions):
    lines = [
        "# Risk and Audit Findings Report",
        "",
        f"Transactions reviewed: {total_transactions}",
        f"Findings: {len(findings)}",
        "",
    ]
    if not findings:
        lines.append("No risk patterns flagged in this data set.")
        return "\n".join(lines) + "\n"
    by_severity = defaultdict(list)
    for finding in findings:
        by_severity[finding["severity"]].append(finding)
    for severity in ("High", "Medium", "Low"):
        group = by_severity.get(severity, [])
        if not group:
            continue
        lines.append(f"## {severity} ({len(group)})")
        lines.append("")
        for finding in group:
            lines.append(f"- **{finding['rule']}** — {finding['transaction_id']}: {finding['detail']}")
        lines.append("")
    lines.append("## Recommended next steps")
    lines.append("")
    lines.append("1. Confirm duplicate and split payments with the vendor and the payment team before reversing anything.")
    lines.append("2. Verify every vendor bank-account change against an independently confirmed source, not the change request itself.")
    lines.append("3. Review segregation-of-duties violations with the control owner and reassign approval authority where needed.")
    lines.append("4. Treat Medium and Low findings as leads for sampling, not conclusions.")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze transactions for audit and risk patterns.")
    parser.add_argument("--input", required=True, help="Input transactions CSV")
    parser.add_argument("--report", help="Output Markdown report path")
    parser.add_argument("--json", help="Output JSON findings path")
    parser.add_argument("--quiet", action="store_true", help="Suppress console summary")
    args = parser.parse_args(argv)

    rows = load_transactions(args.input)
    findings = analyze(rows)
    report = render_report(findings, len(rows))

    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(report)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(findings, handle, indent=2)

    if not args.quiet:
        print(f"Transactions reviewed: {len(rows)}")
        print(f"Findings: {len(findings)}")
        counts = defaultdict(int)
        for finding in findings:
            counts[finding["severity"]] += 1
        for severity in ("High", "Medium", "Low"):
            if counts[severity]:
                print(f"  {severity}: {counts[severity]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
