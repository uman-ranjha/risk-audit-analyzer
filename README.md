# Risk Audit Analyzer

I built this after looking at what risk and audit internships actually ask for. A lot of that work is not catching hackers, it is catching bad payments: the same invoice paid twice, a big purchase split into smaller ones to dodge an approval limit, someone approving their own request, or a vendor suddenly getting paid to a different bank account. I wanted a tool that finds those patterns the way an auditor would, and writes them up so someone can follow up on them.

## What it does

It reads a CSV of transactions and flags seven patterns, ranked by severity:

- **Duplicate payment (High)** — same vendor, amount, and date as an earlier transaction
- **Split transaction (High)** — several payments to one vendor on one day that add up past the $10,000 approval threshold, with each payment alone staying under it
- **Segregation of duties violation (High)** — the requester and approver are the same person
- **Vendor bank account change (Medium)** — a vendor that was paid to one account is suddenly paid to another
- **After-hours approval (Medium)** — approvals outside 08:00–18:00
- **High-value payment (Medium)** — a single payment over $25,000
- **Round-dollar payment (Low)** — exact multiples of $1,000, which mean very little on their own but are worth noting alongside other flags

The output is a severity-ranked Markdown report with recommended next steps, plus a JSON file with the same findings for tracking. I was careful about one thing: a flag is a lead, not a conclusion. The report says that, and the next steps say to confirm with the vendor and the payment team before reversing anything.

## How to run it

```bash
python3 risk_analyzer.py --input samples/transactions.csv --report report.md --json findings.json
```

Only the Python standard library is needed, no extra packages.

## Sample data

`samples/transactions.csv` is 12 made-up transactions. It is not real company data. Running the tool on it gives 9 findings: 3 High, 3 Medium, and 3 Low, covering every rule above. I made the sample that way on purpose, so anyone can see each rule fire at least once.

## Tests

9 tests, all passing. They cover each rule, plus the cases that should *not* flag: different amounts are not duplicates, and totals under the threshold are not split transactions.

## What I learned

The interesting part was not the code, it was deciding what counts as a flag. A round-dollar payment on its own is almost meaningless, and an after-hours approval could just be someone working late. The patterns that actually matter are the ones that combine: a split transaction, a bank account change, or nobody independently approving a payment. That is the difference between a report full of noise and one an auditor would actually act on.
