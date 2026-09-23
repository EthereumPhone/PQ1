"""PQ1 conformance checker — `python3 -m tools.check`.

Deterministic rules over the live code (pq1/, screens/, flows/) and the docs:
the design laws that used to live only in prose. Today's known exceptions
are listed, one by one and with a reason, in baseline.toml — so a clean tree
passes, and any NEW violation fails. See .claude/skills/pq1-conformance/SKILL.md.
"""
