Security dependency bump (2026-01-27)

Summary
-------
This branch documents and groups the security-related dependency upgrades applied to the project and provides test notes.

Changes already applied to `main` (already present):
- Jinja2 -> 3.1.6
- Werkzeug -> 2.3.8
- requests -> 2.32.4
- brotli -> >=1.1.1
- python-socketio -> 5.14.0

What this draft contains
------------------------
- This document listing the CVEs and upgrades
- Validation commands used locally to verify tests

Local validation steps performed
-------------------------------
1. pip install -r data/requirements.txt
2. pytest tests/ -q

Notes & follow-up
-----------------
- Some vulnerabilities require further follow-up if tests or integration fail (e.g. socket/websocket behaviour). We recommend a staged release and smoke tests in staging.
- CI is configured to upload `safety-report.json` artifact for each run; consult it for exact CVE IDs and paths.

If you authorize, I will open this as a draft PR and attach the `safety-report.json` artifact and the test results as comments for review.
