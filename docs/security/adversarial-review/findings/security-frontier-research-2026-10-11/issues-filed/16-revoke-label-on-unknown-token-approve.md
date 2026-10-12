TITLE: approve(addr, 0) on a contract with no token metadata renders "Revoke approval"; on an ERC-721 contract the same call grants token 0
LABELS: finding,priority:low,surface:clear-signing,surface:trusted-ui,source:frontier-research-2026-10
---
## Summary

`approve(address,uint256)` has the same selector (`0x095ea7b3`) on ERC-20 and ERC-721. On ERC-20 a zero amount revokes an allowance. On ERC-721 the second argument is a token id, so the same bytes **grant** approval for token 0. On the unknown-token path the trusted display labels the zero case "Revoke approval" without knowing which standard the contract implements.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- `secure/src/tx/display/erc20_unknown.rs:90-97`: `else if matches!(call, Erc20Call::Approve { .. }) && amount.is_zero() { ... write_line(&mut pages.buf[p][1], "Revoke approval"); }`. The comment says it is "the same framing as the known-token header" (#474).
- `secure/src/tx/display/dispatch.rs:1104-1145`: a direct call with no bound metadata routes to `render_erc20_unknown_pages`.
- `pqsigner-erc7730/src/display/primitives.rs:1238-1241`: the comment dismisses the token-id reading only for the authenticated helper ("the unknown-token path never calls this helper"). The unknown path carries its own copy of the string.
- `secure/src/display_under_test/pure_tests.rs:893`: `positive_unknown_token_zero_approve_paints_revoke_framing` asserts this rendering as intended behaviour. The ERC-721 reading has no test.

https://github.com/EthereumPhone/PQ1/blob/0feea78a1b8bd5ecaa99c3346a5a69480fd13cbc/secure/src/tx/display/erc20_unknown.rs#L90-L97

## What the user sees

On the shipping 16x4 path the call renders eight pages. Page 0 is "! Unknown token" / "approve" / "(decimals = ?)". Page 3 is "Amount (raw):" / "Revoke approval". The warning and the reassuring label are on different pages.

## Scope

A direct call, to a contract that is in neither the token database nor the pinned ERC-7730 call set, with a second argument of 0. A tuple known to the ERC-7730 registry is refused or rendered by that path first. The Safe-inner unknown path prints "Raw amount:" with no revoke wording.

## Severity and evidence level

- Severity: **low-medium**. Exploitation needs the wallet to own token id 0 of an NFT contract outside both databases.
- Evidence: code read; re-checked independently (confirmed). Not run on a device.

## Fix directions

- [ ] On the unknown-token path, do not print "Revoke approval". Print the raw value, and for zero add a line such as "0 (ERC-20: revoke / NFT: token #0)".
- [ ] Keep "Revoke approval" only where the token metadata is authenticated.
- [ ] Replace the test with one that pins the new wording and add the ERC-721 case.

## Related

#474 (introduced the framing, closed), #343.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item CS-07, defect row A24). Re-checked before filing by an independent read at `c75b0d9c` (confirmed, with corrections applied here: the "(RAW) approve" string belongs to the pixel UI only, and a host test does cover the rendering). The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>
