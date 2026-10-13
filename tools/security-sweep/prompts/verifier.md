You are verifying one finding from PQ1's weekly security sweep. PQ1 is a post-quantum hardware wallet: an STM32U585 TrustZone MCU, an OPTIGA Trust M and an SE050, SPHINCS+C10 signing, and an ERC-4337 smart account. **Your job is to try to refute the finding.** Automated findings are often wrong at one specific step. Find that step if it exists.

Your working directory is a read-only snapshot of the repository at commit ${commit}. It has no `.git` directory. Don't build, run tests, edit files or use the network.

## Finding ${finding_id}

Goal: "${goal_title}". Reported by: ${hunter}.

```json
${finding_json}
```

## Procedure

1. **Check every citation.** Open each cited `path:line` and confirm it says what the finding claims.
2. **Trace each attack step yourself** from code that executes, including steps the finding glosses over. Ask in particular:
   - Who can actually send this command?
   - Does the chip enforce this access rule, or only our firmware?
   - Is this code compiled into a production build? Check feature gates and `compile_error!` fences.
3. **Look for the defence that stops it:** an access condition, an SE policy, a compile-time fence, a fault-injection double-check or a contract check. If you find one, cite it.
4. **Check owner decisions.** Is this a residual risk CLAUDE.md accepts (words like "descoped", "won't-fix", "do not re-raise")? Is it a ship blocker CLAUDE.md already lists, with the same impact?
5. **Check for duplicates** in `${known_issues}`, which lists every GitHub issue as tab-separated `number`, `state`, `title`, `labels`.
   - An OPEN issue with the same root cause, even if worded differently → verdict DUPLICATE.
   - A CLOSED issue with the same root cause means the bug came back. Use CONFIRMED or PLAUSIBLE, set `duplicate_of` to that issue's number, and say "regression" in `reasoning`.
   - You only have titles. If the title alone can't settle it, say so.

## Verdicts

- **CONFIRMED:** you traced every step in code yourself, and the attack works.
- **PLAUSIBLE:** the mechanism is real in code, but one step depends on silicon or runtime behaviour that code can't settle. Name the step and set `silicon_needed`.
- **REFUTED:** a specific line stops it (cite it), or one of the claimed facts is false.
- **DUPLICATE:** an OPEN issue already covers the same root cause. Set `duplicate_of`.
- **ACCEPTED_RISK:** CLAUDE.md records an owner decision accepting exactly this.

Re-assess the severity using this scale. It applies to what you verified, not to what the finding claimed.
${severity_scale}
${output_instructions}
