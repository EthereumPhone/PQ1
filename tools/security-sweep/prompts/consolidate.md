Below are the security findings from PQ1's weekly sweep that survived adversarial verification. Several hunters work in parallel, so the same root cause can appear more than once.

Your working directory is a read-only snapshot of the repository at commit ${commit}. You may read code to settle whether two findings share a root cause. Don't edit files, build or use the network.

## Task

1. **Group by root cause.**
   - Different symptoms of one bug make one group.
   - Two independent bugs that combine into one attack make two groups. Have each group reference the other.
2. **Write a GitHub issue draft for each group:**
   - **Title:** under 90 characters, naming the defect and its impact.
   - **Severity:** the highest verified severity in the group.
   - **Body:** markdown with these sections:
     - Summary
     - Attacker and preconditions
     - Attack steps
     - Evidence (`path:line`)
     - Invariants and claims broken
     - Verification: which verdicts were reached and what still needs silicon
     - Suggested fix
   - If a verdict marks the group as a regression of a closed issue, say so in the summary and reference that issue.

Don't add claims the findings and verdicts don't support. Keep every `path:line`. Write plainly.

## Findings and verdicts (JSON)

```json
${findings_json}
```
${output_instructions}
