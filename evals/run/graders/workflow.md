---
type: llm
---
The final summary of the audit run follows the documented workflow and is honest about what the run could check:
1. The summary starts from the Source status section of STATUS.md or AUDIT.md (or the status screen) before any finding: it says which sources failed or were skipped (for example osv.dev, CISA KEV, endoflife.date, the registries or git being unavailable) and that their sections are empty, not clean. Only if no source failed may it go straight to findings, such as the shop-web lodash 4.17.20 finding.
2. It does not claim the portfolio is clean or has no vulnerabilities.
3. It reports the run's outcome (the exit code or the status screen's severity line) as read from the tool output or STATUS.md, rather than guessing.
