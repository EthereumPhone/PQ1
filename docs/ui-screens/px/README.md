# Pixel trusted-UI screens (QEMU `make e2e-px` transcripts)

Every record below is a proven `[UI-PXR]` transcript screen; the PNG is the
settled frame the engine renders for it (`pqsigner-ui-px` `render_record`).
Regenerate with `E2E_LOG_KEEP=/tmp/e2e.log make e2e-px && python3 tools/ui_screens_export.py --px /tmp/e2e.log`.

## Scenario 0h: canonical Safe exec remains signable

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `EXECUTE` | 1 | id=EXECUTE lab="" cap="EXECUTE SAFE TX?" | ![EXECUTE](scenario-0h/00-execute-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-0h/01-network-p0.png) |
| 2 | `SAFEACCT` | 1 | id=SAFEACCT lab="SAFE ACCT" cap="" \| r:0x5a5A5a5a5A5a5a5a5a5 \| r:A5a5A5A5a5a5A5A5A5A5A | ![SAFEACCT](scenario-0h/02-safeacct-p0.png) |
| 3 | `TXINFO` | 1 | id=TXINFO lab="TX INFO" cap="" \| r:Execute now \| r:Op: Call | ![TXINFO](scenario-0h/03-txinfo-p0.png) |
| 4 | `EMPTYCAL` | 1 | id=EMPTYCAL lab="EMPTY CALL" cap="" \| r:0xA5A5A5A5A5A5 \| r:A5A5A5A5a5a5a5 \| r:a5a5a5A5a5a5a5 | ![EMPTYCAL](scenario-0h/04-emptycal-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-0h/05-confirm-p0.png) |
| 6 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-0h/06-maxfee-p0.png) |
| 7 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-0h/07-worst-p0.png) |
| 8 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-0h/08-signer-p0.png) |
| 9 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0x5a5A5a5a5A5a5a5a5a5 \| r:A5a5A5A5a5a5A5A5A5A5A | ![TARGET](scenario-0h/09-target-p0.png) |
| 10 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-0h/10-gaslane-p0.png) |
| 10 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-0h/10-gaslane-p1.png) |
| 11 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-0h/11-fp8213-p0.png) |
| 12 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x65a2f079b0f8a8dab455a6 \| r:d59796e93aa75e2bb981b9 \| r:d2da4c074b1c3e8bc4c4 | ![DIGEST](scenario-0h/12-digest-p0.png) |
| 13 | `EXECUTE` | 1 | id=EXECUTE lab="" cap="EXECUTE SAFE TX?" | ![EXECUTE](scenario-0h/13-execute-p0.png) |

## Scenario 1: register slot 1 on chain A (Type 1 + Type 2)

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 1.0 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-1/d1-00-rotate-p0.png) |
| 1.1 | `ROTATE` | 1 | id=ROTATE lab="ROTATE" cap="" \| r:New signing slot \| r:Slot 1 | ![ROTATE](scenario-1/d1-01-rotate-p0.png) |
| 1.2 | `COST` | 1 | id=COST lab="COST" cap="" \| r:+1 bootstrap use \| r:(on-chain cap) | ![COST](scenario-1/d1-02-cost-p0.png) |
| 1.3 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-1/d1-03-signer-p0.png) |
| 1.4 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-1/d1-04-gaslane-p0.png) |
| 1.4 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-1/d1-04-gaslane-p1.png) |
| 1.5 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-1/d1-05-rotate-p0.png) |
| 2.0 | `SEND` | 1 | id=SEND lab="" cap="SEND 1.000000 ETH?" | ![SEND](scenario-1/d2-00-send-p0.png) |
| 2.1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-1/d2-01-network-p0.png) |
| 2.2 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xabCDEF1234567890ABc \| r:DEF1234567890aBCDeF12 | ![TO](scenario-1/d2-02-to-p0.png) |
| 2.3 | `VALUE` | 1 | id=VALUE lab="VALUE" cap="" \| r:1.000000 ETH | ![VALUE](scenario-1/d2-03-value-p0.png) |
| 2.4 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-1/d2-04-maxfee-p0.png) |
| 2.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-1/d2-05-confirm-p0.png) |
| 2.6 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-1/d2-06-worst-p0.png) |
| 2.7 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 2 \| r:Data: 0 B | ![DETAILS](scenario-1/d2-07-details-p0.png) |
| 2.8 | `NATIVE` | 1 | id=NATIVE lab="NATIVE VALUE" cap="" \| r:! NATIVE ETH \| r:1.000000 ETH | ![NATIVE](scenario-1/d2-08-native-p0.png) |
| 2.9 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-1/d2-09-signer-p0.png) |
| 2.10 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xabCDEF1234567890ABc \| r:DEF1234567890aBCDeF12 | ![TARGET](scenario-1/d2-10-target-p0.png) |
| 2.11 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-1/d2-11-gaslane-p0.png) |
| 2.11 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-1/d2-11-gaslane-p1.png) |
| 2.12 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-1/d2-12-fp8213-p0.png) |
| 2.13 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x290decd9548b62a8d60345 \| r:a988386fc84ba6bc954840 \| r:08f6362f93160ef3e563 | ![DIGEST](scenario-1/d2-13-digest-p0.png) |
| 2.14 | `SEND` | 1 | id=SEND lab="" cap="SEND 1.000000 ETH?" | ![SEND](scenario-1/d2-14-send-p0.png) |

## Scenario 2: repeat sign on chain A slot 1 (Type 2 only)

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.500000 ETH?" | ![SEND](scenario-2/00-send-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-2/01-network-p0.png) |
| 2 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xabCDEF1234567890ABc \| r:DEF1234567890aBCDeF12 | ![TO](scenario-2/02-to-p0.png) |
| 3 | `VALUE` | 1 | id=VALUE lab="VALUE" cap="" \| r:0.500000 ETH | ![VALUE](scenario-2/03-value-p0.png) |
| 4 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-2/04-maxfee-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-2/05-confirm-p0.png) |
| 6 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-2/06-worst-p0.png) |
| 7 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 2 \| r:Data: 0 B | ![DETAILS](scenario-2/07-details-p0.png) |
| 8 | `NATIVE` | 1 | id=NATIVE lab="NATIVE VALUE" cap="" \| r:! NATIVE ETH \| r:0.500000 ETH | ![NATIVE](scenario-2/08-native-p0.png) |
| 9 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-2/09-signer-p0.png) |
| 10 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xabCDEF1234567890ABc \| r:DEF1234567890aBCDeF12 | ![TARGET](scenario-2/10-target-p0.png) |
| 11 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-2/11-gaslane-p0.png) |
| 11 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-2/11-gaslane-p1.png) |
| 12 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-2/12-fp8213-p0.png) |
| 13 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x290decd9548b62a8d60345 \| r:a988386fc84ba6bc954840 \| r:08f6362f93160ef3e563 | ![DIGEST](scenario-2/13-digest-p0.png) |
| 14 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.500000 ETH?" | ![SEND](scenario-2/14-send-p0.png) |

## Scenario 3: rotate to slot 2 on chain A (Type 1 + Type 2)

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 1.0 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-3/d1-00-rotate-p0.png) |
| 1.1 | `ROTATE` | 1 | id=ROTATE lab="ROTATE" cap="" \| r:New signing slot \| r:Slot 2 | ![ROTATE](scenario-3/d1-01-rotate-p0.png) |
| 1.2 | `COST` | 1 | id=COST lab="COST" cap="" \| r:+1 bootstrap use \| r:(on-chain cap) | ![COST](scenario-3/d1-02-cost-p0.png) |
| 1.3 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-3/d1-03-signer-p0.png) |
| 1.4 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-3/d1-04-gaslane-p0.png) |
| 1.4 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-3/d1-04-gaslane-p1.png) |
| 1.5 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-3/d1-05-rotate-p0.png) |
| 2.0 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.250000 ETH?" | ![SEND](scenario-3/d2-00-send-p0.png) |
| 2.1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-3/d2-01-network-p0.png) |
| 2.2 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xabCDEF1234567890ABc \| r:DEF1234567890aBCDeF12 | ![TO](scenario-3/d2-02-to-p0.png) |
| 2.3 | `VALUE` | 1 | id=VALUE lab="VALUE" cap="" \| r:0.250000 ETH | ![VALUE](scenario-3/d2-03-value-p0.png) |
| 2.4 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-3/d2-04-maxfee-p0.png) |
| 2.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-3/d2-05-confirm-p0.png) |
| 2.6 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-3/d2-06-worst-p0.png) |
| 2.7 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 4 \| r:Data: 0 B | ![DETAILS](scenario-3/d2-07-details-p0.png) |
| 2.8 | `NATIVE` | 1 | id=NATIVE lab="NATIVE VALUE" cap="" \| r:! NATIVE ETH \| r:0.250000 ETH | ![NATIVE](scenario-3/d2-08-native-p0.png) |
| 2.9 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-3/d2-09-signer-p0.png) |
| 2.10 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xabCDEF1234567890ABc \| r:DEF1234567890aBCDeF12 | ![TARGET](scenario-3/d2-10-target-p0.png) |
| 2.11 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-3/d2-11-gaslane-p0.png) |
| 2.11 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-3/d2-11-gaslane-p1.png) |
| 2.12 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-3/d2-12-fp8213-p0.png) |
| 2.13 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x290decd9548b62a8d60345 \| r:a988386fc84ba6bc954840 \| r:08f6362f93160ef3e563 | ![DIGEST](scenario-3/d2-13-digest-p0.png) |
| 2.14 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.250000 ETH?" | ![SEND](scenario-3/d2-14-send-p0.png) |

## Scenario 4: register slot 1 on chain B (Type 1 + Type 2)

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 1.0 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-4/d1-00-rotate-p0.png) |
| 1.1 | `ROTATE` | 1 | id=ROTATE lab="ROTATE" cap="" \| r:New signing slot \| r:Slot 1 | ![ROTATE](scenario-4/d1-01-rotate-p0.png) |
| 1.2 | `COST` | 1 | id=COST lab="COST" cap="" \| r:+1 bootstrap use \| r:(on-chain cap) | ![COST](scenario-4/d1-02-cost-p0.png) |
| 1.3 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-4/d1-03-signer-p0.png) |
| 1.4 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-4/d1-04-gaslane-p0.png) |
| 1.4 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-4/d1-04-gaslane-p1.png) |
| 1.5 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-4/d1-05-rotate-p0.png) |
| 2.0 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.100000 ETH?" | ![SEND](scenario-4/d2-00-send-p0.png) |
| 2.1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on BaseSepolia | ![NETWORK](scenario-4/d2-01-network-p0.png) |
| 2.2 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xabCDEF1234567890ABc \| r:DEF1234567890aBCDeF12 | ![TO](scenario-4/d2-02-to-p0.png) |
| 2.3 | `VALUE` | 1 | id=VALUE lab="VALUE" cap="" \| r:0.100000 ETH | ![VALUE](scenario-4/d2-03-value-p0.png) |
| 2.4 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-4/d2-04-maxfee-p0.png) |
| 2.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-4/d2-05-confirm-p0.png) |
| 2.6 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-4/d2-06-worst-p0.png) |
| 2.7 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 2 \| r:Data: 0 B | ![DETAILS](scenario-4/d2-07-details-p0.png) |
| 2.8 | `NATIVE` | 1 | id=NATIVE lab="NATIVE VALUE" cap="" \| r:! NATIVE ETH \| r:0.100000 ETH | ![NATIVE](scenario-4/d2-08-native-p0.png) |
| 2.9 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-4/d2-09-signer-p0.png) |
| 2.10 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xabCDEF1234567890ABc \| r:DEF1234567890aBCDeF12 | ![TARGET](scenario-4/d2-10-target-p0.png) |
| 2.11 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-4/d2-11-gaslane-p0.png) |
| 2.11 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-4/d2-11-gaslane-p1.png) |
| 2.12 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-4/d2-12-fp8213-p0.png) |
| 2.13 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x290decd9548b62a8d60345 \| r:a988386fc84ba6bc954840 \| r:08f6362f93160ef3e563 | ![DIGEST](scenario-4/d2-13-digest-p0.png) |
| 2.14 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.100000 ETH?" | ![SEND](scenario-4/d2-14-send-p0.png) |

## Scenario 4a: zero-value contract call

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `CALL` | 1 | id=CALL lab="" cap="CONFIRM CONTRACT CALL?" | ![CALL](scenario-4a/00-call-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-4a/01-network-p0.png) |
| 2 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0x9e3B5c0f7a1d24E86C3 \| r:F0B7d5A2e4C6F8b1D3a7c | ![TO](scenario-4a/02-to-p0.png) |
| 3 | `VALUE` | 1 | id=VALUE lab="VALUE" cap="" \| r:0.000000 ETH | ![VALUE](scenario-4a/03-value-p0.png) |
| 4 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-4a/04-maxfee-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-4a/05-confirm-p0.png) |
| 6 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-4a/06-worst-p0.png) |
| 7 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 4 \| r:Data: 0 B | ![DETAILS](scenario-4a/07-details-p0.png) |
| 8 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-4a/08-signer-p0.png) |
| 9 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0x9e3B5c0f7a1d24E86C3 \| r:F0B7d5A2e4C6F8b1D3a7c | ![TARGET](scenario-4a/09-target-p0.png) |
| 10 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-4a/10-gaslane-p0.png) |
| 10 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-4a/10-gaslane-p1.png) |
| 11 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-4a/11-fp8213-p0.png) |
| 12 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x290decd9548b62a8d60345 \| r:a988386fc84ba6bc954840 \| r:08f6362f93160ef3e563 | ![DIGEST](scenario-4a/12-digest-p0.png) |
| 13 | `CALL` | 1 | id=CALL lab="" cap="CONFIRM CONTRACT CALL?" | ![CALL](scenario-4a/13-call-p0.png) |

## Scenario 4b: unknown-token ERC-20 transfer

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `TRANSFER` | 1 | id=TRANSFER lab="" cap="TRANSFER UNKNOWN TOKEN?" | ![TRANSFER](scenario-4b/00-transfer-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-4b/01-network-p0.png) |
| 2 | `CONTRACT` | 1 | id=CONTRACT lab="CONTRACT" cap="" \| s:! Unknown token \| r:0x3ca9e5f1B72D04e8A6c \| r:1d9b3f57e28a0c4d6B1e9 | ![CONTRACT](scenario-4b/02-contract-p0.png) |
| 3 | `AMOUNT` | 1 | id=AMOUNT lab="AMOUNT" cap="" \| r:(RAW) transfer \| r:12345678901234567890 | ![AMOUNT](scenario-4b/03-amount-p0.png) |
| 4 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xabCDEF1234567890ABc \| r:DEF1234567890aBCDeF12 | ![TO](scenario-4b/04-to-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-4b/05-confirm-p0.png) |
| 6 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-4b/06-maxfee-p0.png) |
| 7 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-4b/07-worst-p0.png) |
| 8 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 5 \| r:Data: 68 B | ![DETAILS](scenario-4b/08-details-p0.png) |
| 9 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-4b/09-signer-p0.png) |
| 10 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0x3ca9e5f1B72D04e8A6c \| r:1d9b3f57e28a0c4d6B1e9 | ![TARGET](scenario-4b/10-target-p0.png) |
| 11 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-4b/11-gaslane-p0.png) |
| 11 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-4b/11-gaslane-p1.png) |
| 12 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-4b/12-fp8213-p0.png) |
| 13 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x4cfc6bb43edee633da3d63 \| r:6f5e562fda90cc4474bd93 \| r:b6b641dabcebb2885888 | ![DIGEST](scenario-4b/13-digest-p0.png) |
| 14 | `TRANSFER` | 1 | id=TRANSFER lab="" cap="TRANSFER UNKNOWN TOKEN?" | ![TRANSFER](scenario-4b/14-transfer-p0.png) |

## Scenario 4c: first deploy with initCode

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.010000 ETH?" | ![SEND](scenario-4c/00-send-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Base | ![NETWORK](scenario-4c/01-network-p0.png) |
| 2 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xabCDEF1234567890ABc \| r:DEF1234567890aBCDeF12 | ![TO](scenario-4c/02-to-p0.png) |
| 3 | `VALUE` | 1 | id=VALUE lab="VALUE" cap="" \| r:0.010000 ETH | ![VALUE](scenario-4c/03-value-p0.png) |
| 4 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-4c/04-maxfee-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-4c/05-confirm-p0.png) |
| 6 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-4c/06-worst-p0.png) |
| 7 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 0 \| r:Data: 0 B | ![DETAILS](scenario-4c/07-details-p0.png) |
| 8 | `NATIVE` | 1 | id=NATIVE lab="NATIVE VALUE" cap="" \| r:! NATIVE ETH \| r:0.010000 ETH | ![NATIVE](scenario-4c/08-native-p0.png) |
| 9 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-4c/09-signer-p0.png) |
| 10 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xabCDEF1234567890ABc \| r:DEF1234567890aBCDeF12 | ![TARGET](scenario-4c/10-target-p0.png) |
| 11 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-4c/11-gaslane-p0.png) |
| 11 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-4c/11-gaslane-p1.png) |
| 12 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-4c/12-fp8213-p0.png) |
| 13 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x290decd9548b62a8d60345 \| r:a988386fc84ba6bc954840 \| r:08f6362f93160ef3e563 | ![DIGEST](scenario-4c/13-digest-p0.png) |
| 14 | `DEPLOY` | 1 | id=DEPLOY lab="! DEPLOY" cap="" \| s:DEPLOY FACTORY: \| r:0xe8CE78CD976497447FF \| r:8B76c71b59aE42Af0d452 | ![DEPLOY](scenario-4c/14-deploy-p0.png) |
| 15 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.010000 ETH?" | ![SEND](scenario-4c/15-send-p0.png) |

## Scenario 5: Safe approveHash clear-sign

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `APPROVE` | 1 | id=APPROVE lab="" cap="APPROVE SAFE TX?" | ![APPROVE](scenario-5/00-approve-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5/01-network-p0.png) |
| 2 | `SAFEACCT` | 1 | id=SAFEACCT lab="SAFE ACCT" cap="" \| r:0x5aFE000000000000000 \| r:000000000000000000001 | ![SAFEACCT](scenario-5/02-safeacct-p0.png) |
| 3 | `TXINFO` | 1 | id=TXINFO lab="TX INFO" cap="" \| r:Nonce: 17 \| r:Op: Call | ![TXINFO](scenario-5/03-txinfo-p0.png) |
| 4 | `UNVERIF` | 1 | id=UNVERIF lab="UNVERIFIED" cap="" \| r:ERC-20 call \| r:token unknown | ![UNVERIF](scenario-5/04-unverif-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5/05-confirm-p0.png) |
| 6 | `RAWAMT` | 1 | id=RAWAMT lab="RAW AMOUNT" cap="" \| r:250000000 units | ![RAWAMT](scenario-5/06-rawamt-p0.png) |
| 7 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xABaBaBaBABab \| r:ABabAbAbABAbAB \| r:abababaBaBABaB | ![TO](scenario-5/07-to-p0.png) |
| 8 | `CONTRACT` | 1 | id=CONTRACT lab="CONTRACT" cap="" \| r:0xA0b86991c6218b36c1d \| r:19D4a2e9Eb0cE3606eB48 | ![CONTRACT](scenario-5/08-contract-p0.png) |
| 9 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5/09-maxfee-p0.png) |
| 10 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-5/10-worst-p0.png) |
| 11 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5/11-signer-p0.png) |
| 12 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0x5aFE000000000000000 \| r:000000000000000000001 | ![TARGET](scenario-5/12-target-p0.png) |
| 13 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5/13-gaslane-p0.png) |
| 13 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5/13-gaslane-p1.png) |
| 14 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5/14-fp8213-p0.png) |
| 15 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x20d91e6a7ee38f31d0d8d8 \| r:88544c928f98b94e3e71b6 \| r:8934caef277f253c4600 | ![DIGEST](scenario-5/15-digest-p0.png) |
| 16 | `APPROVE` | 1 | id=APPROVE lab="" cap="APPROVE SAFE TX?" | ![APPROVE](scenario-5/16-approve-p0.png) |

## Scenario 5b: verified function-selector bundle

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `BLIND` | 1 | id=BLIND lab="" cap="CONFIRM BLIND SIGN?" | ![BLIND](scenario-5b/00-blind-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5b/01-network-p0.png) |
| 2 | `FUNCTION` | 1 | id=FUNCTION lab="FUNCTION" cap="" \| s:! BLIND SIGN \| r:balanceOf(address) | ![FUNCTION](scenario-5b/02-function-p0.png) |
| 3 | `ARG0` | 1 | id=ARG0 lab="ARG 0" cap="" \| r:0xABaBaBaBABab \| r:ABabAbAbABAbAB \| r:abababaBaBABaB | ![ARG0](scenario-5b/03-arg0-p0.png) |
| 4 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xfefeFEFeFEFEFEFEFeF \| r:efefefefeFEfEfefefEfe | ![TO](scenario-5b/04-to-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5b/05-confirm-p0.png) |
| 6 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5b/06-maxfee-p0.png) |
| 7 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-5b/07-worst-p0.png) |
| 8 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 5 \| r:Data: 36 B | ![DETAILS](scenario-5b/08-details-p0.png) |
| 9 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5b/09-signer-p0.png) |
| 10 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xfefeFEFeFEFEFEFEFeF \| r:efefefefeFEfEfefefEfe | ![TARGET](scenario-5b/10-target-p0.png) |
| 11 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5b/11-gaslane-p0.png) |
| 11 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5b/11-gaslane-p1.png) |
| 12 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5b/12-fp8213-p0.png) |
| 13 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x29a9350d4d0b50ba49a7f2 \| r:457e9b95ba29bacacaef97 \| r:354f9ec01d0cb404ea22 | ![DIGEST](scenario-5b/13-digest-p0.png) |
| 14 | `BLIND` | 1 | id=BLIND lab="" cap="CONFIRM BLIND SIGN?" | ![BLIND](scenario-5b/14-blind-p0.png) |

## Scenario 5v: companion-supplied ERC-20 metadata trailer

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 1.0 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-5v/d1-00-rotate-p0.png) |
| 1.1 | `ROTATE` | 1 | id=ROTATE lab="ROTATE" cap="" \| r:New signing slot \| r:Slot 5 | ![ROTATE](scenario-5v/d1-01-rotate-p0.png) |
| 1.2 | `COST` | 1 | id=COST lab="COST" cap="" \| r:+1 bootstrap use \| r:(on-chain cap) | ![COST](scenario-5v/d1-02-cost-p0.png) |
| 1.3 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5v/d1-03-signer-p0.png) |
| 1.4 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5v/d1-04-gaslane-p0.png) |
| 1.4 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5v/d1-04-gaslane-p1.png) |
| 1.5 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-5v/d1-05-rotate-p0.png) |
| 2.0 | `SEND` | 1 | id=SEND lab="" cap="SEND 123.45 TEL?" | ![SEND](scenario-5v/d2-00-send-p0.png) |
| 2.1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Base | ![NETWORK](scenario-5v/d2-01-network-p0.png) |
| 2.2 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xCdCDCdCdcdcd \| r:cdCdcDcDCdcDcD \| r:CdCdcdCdcDCDcD | ![TO](scenario-5v/d2-02-to-p0.png) |
| 2.3 | `AMOUNT` | 1 | id=AMOUNT lab="SEND" cap="" \| r:123.45 TEL | ![AMOUNT](scenario-5v/d2-03-amount-p0.png) |
| 2.4 | `CONTRACT` | 1 | id=CONTRACT lab="CONTRACT" cap="" \| s:Telcoin \| r:0x09bE1692ca16e06f536 \| r:F0038fF11D1dA8524aDB1 | ![CONTRACT](scenario-5v/d2-04-contract-p0.png) |
| 2.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5v/d2-05-confirm-p0.png) |
| 2.6 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5v/d2-06-maxfee-p0.png) |
| 2.7 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-5v/d2-07-worst-p0.png) |
| 2.8 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 7 \| r:Data: 68 B | ![DETAILS](scenario-5v/d2-08-details-p0.png) |
| 2.9 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5v/d2-09-signer-p0.png) |
| 2.10 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0x09bE1692ca16e06f536 \| r:F0038fF11D1dA8524aDB1 | ![TARGET](scenario-5v/d2-10-target-p0.png) |
| 2.11 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5v/d2-11-gaslane-p0.png) |
| 2.11 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5v/d2-11-gaslane-p1.png) |
| 2.12 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5v/d2-12-fp8213-p0.png) |
| 2.13 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x15228560450644904b77c1 \| r:80fd36b793f2088410cbad \| r:d6886f38aca39ab36ca9 | ![DIGEST](scenario-5v/d2-13-digest-p0.png) |
| 2.14 | `SEND` | 1 | id=SEND lab="" cap="SEND 123.45 TEL?" | ![SEND](scenario-5v/d2-14-send-p0.png) |

## Scenario 5m-nested: ERC-7730 nested proof set matches + signs

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-5m-nested/00-rotate-p0.png) |
| 1 | `ROTATE` | 1 | id=ROTATE lab="ROTATE" cap="" \| r:New signing slot \| r:Slot 1 | ![ROTATE](scenario-5m-nested/01-rotate-p0.png) |
| 2 | `COST` | 1 | id=COST lab="COST" cap="" \| r:+1 bootstrap use \| r:(on-chain cap) | ![COST](scenario-5m-nested/02-cost-p0.png) |
| 3 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5m-nested/03-signer-p0.png) |
| 4 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5m-nested/04-gaslane-p0.png) |
| 4 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5m-nested/04-gaslane-p1.png) |
| 5 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-5m-nested/05-rotate-p0.png) |

## Scenario 5w: companion-supplied address-name trailer

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 1.0 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-5w/d1-00-rotate-p0.png) |
| 1.1 | `ROTATE` | 1 | id=ROTATE lab="ROTATE" cap="" \| r:New signing slot \| r:Slot 6 | ![ROTATE](scenario-5w/d1-01-rotate-p0.png) |
| 1.2 | `COST` | 1 | id=COST lab="COST" cap="" \| r:+1 bootstrap use \| r:(on-chain cap) | ![COST](scenario-5w/d1-02-cost-p0.png) |
| 1.3 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5w/d1-03-signer-p0.png) |
| 1.4 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5w/d1-04-gaslane-p0.png) |
| 1.4 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5w/d1-04-gaslane-p1.png) |
| 1.5 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-5w/d1-05-rotate-p0.png) |
| 2.0 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.000001 ETH?" | ![SEND](scenario-5w/d2-00-send-p0.png) |
| 2.1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Base | ![NETWORK](scenario-5w/d2-01-network-p0.png) |
| 2.2 | `TO` | 1 | id=TO lab="TO" cap="" \| s:Uniswap V3 Router \| r:0xE592427A0AEce92De3E \| r:dee1F18E0157C05861564 | ![TO](scenario-5w/d2-02-to-p0.png) |
| 2.3 | `VALUE` | 1 | id=VALUE lab="VALUE" cap="" \| r:0.000001 ETH | ![VALUE](scenario-5w/d2-03-value-p0.png) |
| 2.4 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5w/d2-04-maxfee-p0.png) |
| 2.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5w/d2-05-confirm-p0.png) |
| 2.6 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-5w/d2-06-worst-p0.png) |
| 2.7 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 8 \| r:Data: 0 B | ![DETAILS](scenario-5w/d2-07-details-p0.png) |
| 2.8 | `NATIVE` | 1 | id=NATIVE lab="NATIVE VALUE" cap="" \| r:! NATIVE ETH \| r:0.000001 ETH | ![NATIVE](scenario-5w/d2-08-native-p0.png) |
| 2.9 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5w/d2-09-signer-p0.png) |
| 2.10 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xE592427A0AEce92De3E \| r:dee1F18E0157C05861564 | ![TARGET](scenario-5w/d2-10-target-p0.png) |
| 2.11 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5w/d2-11-gaslane-p0.png) |
| 2.11 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5w/d2-11-gaslane-p1.png) |
| 2.12 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5w/d2-12-fp8213-p0.png) |
| 2.13 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x290decd9548b62a8d60345 \| r:a988386fc84ba6bc954840 \| r:08f6362f93160ef3e563 | ![DIGEST](scenario-5w/d2-13-digest-p0.png) |
| 2.14 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.000001 ETH?" | ![SEND](scenario-5w/d2-14-send-p0.png) |

## Scenario 5c: cross-check rejects mismatched selector

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `UNKNOWN` | 1 | id=UNKNOWN lab="" cap="CONFIRM UNKNOWN CALL?" | ![UNKNOWN](scenario-5c/00-unknown-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5c/01-network-p0.png) |
| 2 | `BLINDSGN` | 1 | id=BLINDSGN lab="BLIND SIGN" cap="" \| r:Unknown call \| r:Verify on dapp | ![BLINDSGN](scenario-5c/02-blindsgn-p0.png) |
| 3 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xfefeFEFeFEFEFEFEFeF \| r:efefefefeFEfEfefefEfe | ![TO](scenario-5c/03-to-p0.png) |
| 4 | `AMOUNT` | 1 | id=AMOUNT lab="AMOUNT" cap="" \| r:0 ETH | ![AMOUNT](scenario-5c/04-amount-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5c/05-confirm-p0.png) |
| 6 | `CALLDATA` | 1 | id=CALLDATA lab="CALL DATA" cap="" \| r:Selector: 0x70a08231 \| r:Data: 36 B | ![CALLDATA](scenario-5c/06-calldata-p0.png) |
| 7 | `DATAHASH` | 1 | id=DATAHASH lab="DATA HASH" cap="" \| r:0xfb7d093103926e09abdf24 \| r:01b035d74cdee4ed9f448c \| r:fea20659cce733370e23 | ![DATAHASH](scenario-5c/07-datahash-p0.png) |
| 8 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5c/08-maxfee-p0.png) |
| 9 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-5c/09-worst-p0.png) |
| 10 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 6 \| r:Data: 36 B | ![DETAILS](scenario-5c/10-details-p0.png) |
| 11 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5c/11-signer-p0.png) |
| 12 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xfefeFEFeFEFEFEFEFeF \| r:efefefefeFEfEfefefEfe | ![TARGET](scenario-5c/12-target-p0.png) |
| 13 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5c/13-gaslane-p0.png) |
| 13 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5c/13-gaslane-p1.png) |
| 14 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5c/14-fp8213-p0.png) |
| 15 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x29a9350d4d0b50ba49a7f2 \| r:457e9b95ba29bacacaef97 \| r:354f9ec01d0cb404ea22 | ![DIGEST](scenario-5c/15-digest-p0.png) |
| 16 | `UNKNOWN` | 1 | id=UNKNOWN lab="" cap="CONFIRM UNKNOWN CALL?" | ![UNKNOWN](scenario-5c/16-unknown-p0.png) |

## Scenario 5d: typed walker declines, blind-sign fallback

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `UNKNOWN` | 1 | id=UNKNOWN lab="" cap="CONFIRM UNKNOWN CALL?" | ![UNKNOWN](scenario-5d/00-unknown-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5d/01-network-p0.png) |
| 2 | `BLINDSGN` | 1 | id=BLINDSGN lab="BLIND SIGN" cap="" \| r:Unknown call \| r:Verify on dapp | ![BLINDSGN](scenario-5d/02-blindsgn-p0.png) |
| 3 | `FUNCTION` | 1 | id=FUNCTION lab="FUNCTION" cap="" \| r:transfer(address, \| r:uint256) | ![FUNCTION](scenario-5d/03-function-p0.png) |
| 4 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xfefeFEFeFEFEFEFEFeF \| r:efefefefeFEfEfefefEfe | ![TO](scenario-5d/04-to-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5d/05-confirm-p0.png) |
| 6 | `AMOUNT` | 1 | id=AMOUNT lab="AMOUNT" cap="" \| r:0 ETH | ![AMOUNT](scenario-5d/06-amount-p0.png) |
| 7 | `CALLDATA` | 1 | id=CALLDATA lab="CALL DATA" cap="" \| r:Selector: 0xa9059cbb \| r:Data: 36 B | ![CALLDATA](scenario-5d/07-calldata-p0.png) |
| 8 | `DATAHASH` | 1 | id=DATAHASH lab="DATA HASH" cap="" \| r:0x7eba394a6103e6585dddbc \| r:83a85e64ec5abdb339bd13 \| r:bf4e995fbcbe4735416a | ![DATAHASH](scenario-5d/08-datahash-p0.png) |
| 9 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5d/09-maxfee-p0.png) |
| 10 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-5d/10-worst-p0.png) |
| 11 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 7 \| r:Data: 36 B | ![DETAILS](scenario-5d/11-details-p0.png) |
| 12 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5d/12-signer-p0.png) |
| 13 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xfefeFEFeFEFEFEFEFeF \| r:efefefefeFEfEfefefEfe | ![TARGET](scenario-5d/13-target-p0.png) |
| 14 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5d/14-gaslane-p0.png) |
| 14 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5d/14-gaslane-p1.png) |
| 15 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5d/15-fp8213-p0.png) |
| 16 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x56abc700fd68d31a422773 \| r:9c599304ab9f7626d60db0 \| r:a348ce4d0d10c55d6a00 | ![DIGEST](scenario-5d/16-digest-p0.png) |
| 17 | `UNKNOWN` | 1 | id=UNKNOWN lab="" cap="CONFIRM UNKNOWN CALL?" | ![UNKNOWN](scenario-5d/17-unknown-p0.png) |

## Scenario 5j: self-attest typed render

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `BLIND` | 1 | id=BLIND lab="" cap="CONFIRM UNVERIFIED CALL?" | ![BLIND](scenario-5j/00-blind-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5j/01-network-p0.png) |
| 2 | `GUESS` | 1 | id=GUESS lab="GUESS" cap="" \| s:! UNVERIFIED \| r:transfer(uint256) | ![GUESS](scenario-5j/02-guess-p0.png) |
| 3 | `ARG0` | 1 | id=ARG0 lab="ARG 0" cap="" \| s:uint256: \| r:1000 | ![ARG0](scenario-5j/03-arg0-p0.png) |
| 4 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xfefeFEFeFEFEFEFEFeF \| r:efefefefeFEfEfefefEfe | ![TO](scenario-5j/04-to-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5j/05-confirm-p0.png) |
| 6 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5j/06-maxfee-p0.png) |
| 7 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-5j/07-worst-p0.png) |
| 8 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 8 \| r:Data: 36 B | ![DETAILS](scenario-5j/08-details-p0.png) |
| 9 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5j/09-signer-p0.png) |
| 10 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xfefeFEFeFEFEFEFEFeF \| r:efefefefeFEfEfefefEfe | ![TARGET](scenario-5j/10-target-p0.png) |
| 11 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5j/11-gaslane-p0.png) |
| 11 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5j/11-gaslane-p1.png) |
| 12 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5j/12-fp8213-p0.png) |
| 13 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x5dda91b7c370b5b4f4af26 \| r:138448ff367c360764b4d6 \| r:e1854b58a38b94ccf54a | ![DIGEST](scenario-5j/13-digest-p0.png) |
| 14 | `BLIND` | 1 | id=BLIND lab="" cap="CONFIRM UNVERIFIED CALL?" | ![BLIND](scenario-5j/14-blind-p0.png) |

## Scenario 5k: self-attest keccak mismatch dropped

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `UNKNOWN` | 1 | id=UNKNOWN lab="" cap="CONFIRM UNKNOWN CALL?" | ![UNKNOWN](scenario-5k/00-unknown-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5k/01-network-p0.png) |
| 2 | `BLINDSGN` | 1 | id=BLINDSGN lab="BLIND SIGN" cap="" \| r:Unknown call \| r:Verify on dapp | ![BLINDSGN](scenario-5k/02-blindsgn-p0.png) |
| 3 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xfefeFEFeFEFEFEFEFeF \| r:efefefefeFEfEfefefEfe | ![TO](scenario-5k/03-to-p0.png) |
| 4 | `AMOUNT` | 1 | id=AMOUNT lab="AMOUNT" cap="" \| r:0 ETH | ![AMOUNT](scenario-5k/04-amount-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5k/05-confirm-p0.png) |
| 6 | `CALLDATA` | 1 | id=CALLDATA lab="CALL DATA" cap="" \| r:Selector: 0x12514bba \| r:Data: 36 B | ![CALLDATA](scenario-5k/06-calldata-p0.png) |
| 7 | `DATAHASH` | 1 | id=DATAHASH lab="DATA HASH" cap="" \| r:0x029082bb13b30b74c3c6b9 \| r:743efc970fe06e6782a9e9 \| r:f62d9f75ed5e27ad3ee6 | ![DATAHASH](scenario-5k/07-datahash-p0.png) |
| 8 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5k/08-maxfee-p0.png) |
| 9 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-5k/09-worst-p0.png) |
| 10 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 9 \| r:Data: 36 B | ![DETAILS](scenario-5k/10-details-p0.png) |
| 11 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5k/11-signer-p0.png) |
| 12 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xfefeFEFeFEFEFEFEFeF \| r:efefefefeFEfEfefefEfe | ![TARGET](scenario-5k/12-target-p0.png) |
| 13 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5k/13-gaslane-p0.png) |
| 13 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5k/13-gaslane-p1.png) |
| 14 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5k/14-fp8213-p0.png) |
| 15 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x0a67b1709a8404c63d8213 \| r:c205a30d97c06321160671 \| r:00c7357acfeb24dd6c36 | ![DIGEST](scenario-5k/15-digest-p0.png) |
| 16 | `UNKNOWN` | 1 | id=UNKNOWN lab="" cap="CONFIRM UNKNOWN CALL?" | ![UNKNOWN](scenario-5k/16-unknown-p0.png) |

## Scenario 5q: Safe-wrapped CoW presign clear-sign

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `APPROVE` | 1 | id=APPROVE lab="" cap="APPROVE SAFE TX?" | ![APPROVE](scenario-5q/00-approve-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5q/01-network-p0.png) |
| 2 | `SAFEACCT` | 1 | id=SAFEACCT lab="SAFE ACCT" cap="" \| r:0x5AFE000000000000000 \| r:000000000000000000002 | ![SAFEACCT](scenario-5q/02-safeacct-p0.png) |
| 3 | `TXINFO` | 1 | id=TXINFO lab="TX INFO" cap="" \| r:Nonce: 18 \| r:Op: Call | ![TXINFO](scenario-5q/03-txinfo-p0.png) |
| 4 | `COWORDER` | 1 | id=COWORDER lab="COW ORDER" cap="" \| r:SELL order \| r:owner: this Safe | ![COWORDER](scenario-5q/04-coworder-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5q/05-confirm-p0.png) |
| 6 | `SELLTOK` | 1 | id=SELLTOK lab="SELL TOKEN" cap="" \| r:0xA0b86991c6218b36c1d \| r:19D4a2e9Eb0cE3606eB48 | ![SELLTOK](scenario-5q/06-selltok-p0.png) |
| 7 | `SELLAMT` | 1 | id=SELLAMT lab="SELL" cap="" \| r:0x0000000000000000000000 \| r:0000000000000000000000 \| r:0000000000003b9aca00 | ![SELLAMT](scenario-5q/07-sellamt-p0.png) |
| 8 | `BUYTOK` | 1 | id=BUYTOK lab="BUY TOKEN" cap="" \| r:0xC02aaA39b223 \| r:FE8D0A0e5C4F27 \| r:eAD9083C756Cc2 | ![BUYTOK](scenario-5q/08-buytok-p0.png) |
| 9 | `BUYAMT` | 1 | id=BUYAMT lab="BUY MIN" cap="" \| r:0x0000000000000000000000 \| r:0000000000000000000000 \| r:000006f05b59d3b20000 | ![BUYAMT](scenario-5q/09-buyamt-p0.png) |
| 10 | `RECEIVER` | 1 | id=RECEIVER lab="RECEIVER" cap="" \| r:= the Safe | ![RECEIVER](scenario-5q/10-receiver-p0.png) |
| 11 | `EXPIRES` | 1 | id=EXPIRES lab="EXPIRES" cap="" \| r:unix 1744830464 \| r:Partial: no | ![EXPIRES](scenario-5q/11-expires-p0.png) |
| 12 | `FEE` | 1 | id=FEE lab="FEE (SELL)" cap="" \| r:0 units | ![FEE](scenario-5q/12-fee-p0.png) |
| 13 | `SOURCES` | 1 | id=SOURCES lab="SOURCES" cap="" \| r:sell: erc20 \| r:buy: erc20 | ![SOURCES](scenario-5q/13-sources-p0.png) |
| 14 | `APPDATA` | 1 | id=APPDATA lab="APP DATA" cap="" \| r:0x0000000000000000 \| r:0000000000000000 | ![APPDATA](scenario-5q/14-appdata-p0.png) |
| 14 | `APPDATA` | 2 | id=APPDATA lab="APP DATA" cap="" \| r:0000000000000000 \| r:0000000000000000 | ![APPDATA](scenario-5q/14-appdata-p1.png) |
| 15 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5q/15-maxfee-p0.png) |
| 16 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-5q/16-worst-p0.png) |
| 17 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5q/17-signer-p0.png) |
| 18 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0x5AFE000000000000000 \| r:000000000000000000002 | ![TARGET](scenario-5q/18-target-p0.png) |
| 19 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5q/19-gaslane-p0.png) |
| 19 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5q/19-gaslane-p1.png) |
| 20 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5q/20-fp8213-p0.png) |
| 21 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x3dee5d6d0369427ec99609 \| r:55135f1f30f980b42d9067 \| r:469b908aed5a14b959fd | ![DIGEST](scenario-5q/21-digest-p0.png) |
| 22 | `APPROVE` | 1 | id=APPROVE lab="" cap="APPROVE SAFE TX?" | ![APPROVE](scenario-5q/22-approve-p0.png) |

## Scenario 5s: multiSend (approve+presign) safe-wrapped CoW clear-sign

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `APPROVE` | 1 | id=APPROVE lab="" cap="APPROVE SAFE TX?" | ![APPROVE](scenario-5s/00-approve-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5s/01-network-p0.png) |
| 2 | `SAFEACCT` | 1 | id=SAFEACCT lab="SAFE ACCT" cap="" \| r:0x5AFE000000000000000 \| r:000000000000000000002 | ![SAFEACCT](scenario-5s/02-safeacct-p0.png) |
| 3 | `TXINFO` | 1 | id=TXINFO lab="TX INFO" cap="" \| r:Nonce: 20 \| r:Op: MultiSend x2 | ![TXINFO](scenario-5s/03-txinfo-p0.png) |
| 4 | `RECORD1` | 1 | id=RECORD1 lab="RECORD 1/2" cap="" \| r:0xA0b86991c6218b36c1d \| r:19D4a2e9Eb0cE3606eB48 | ![RECORD1](scenario-5s/04-record1-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5s/05-confirm-p0.png) |
| 6 | `UNVERIF` | 1 | id=UNVERIF lab="UNVERIFIED" cap="" \| r:ERC-20 call \| r:token unknown | ![UNVERIF](scenario-5s/06-unverif-p0.png) |
| 7 | `RAWAMT` | 1 | id=RAWAMT lab="RAW AMOUNT" cap="" \| r:1000000000 units | ![RAWAMT](scenario-5s/07-rawamt-p0.png) |
| 8 | `SPENDER` | 1 | id=SPENDER lab="SPENDER" cap="" \| s:CoW VaultRelayer \| r:0xC92E8bdf79f0507f65a \| r:392b0ab4667716BFE0110 | ![SPENDER](scenario-5s/08-spender-p0.png) |
| 9 | `CONTRACT` | 1 | id=CONTRACT lab="CONTRACT" cap="" \| r:0xA0b86991c6218b36c1d \| r:19D4a2e9Eb0cE3606eB48 | ![CONTRACT](scenario-5s/09-contract-p0.png) |
| 10 | `RECORD2` | 1 | id=RECORD2 lab="RECORD 2/2" cap="" \| r:0x9008D19f58AAbD9eD0D \| r:60971565AA8510560ab41 | ![RECORD2](scenario-5s/10-record2-p0.png) |
| 11 | `COWORDER` | 1 | id=COWORDER lab="COW ORDER" cap="" \| r:SELL order \| r:owner: this Safe | ![COWORDER](scenario-5s/11-coworder-p0.png) |
| 12 | `SELLTOK` | 1 | id=SELLTOK lab="SELL TOKEN" cap="" \| r:0xA0b86991c6218b36c1d \| r:19D4a2e9Eb0cE3606eB48 | ![SELLTOK](scenario-5s/12-selltok-p0.png) |
| 13 | `SELLAMT` | 1 | id=SELLAMT lab="SELL" cap="" \| r:0x0000000000000000000000 \| r:0000000000000000000000 \| r:0000000000003b9aca00 | ![SELLAMT](scenario-5s/13-sellamt-p0.png) |
| 14 | `BUYTOK` | 1 | id=BUYTOK lab="BUY TOKEN" cap="" \| r:0xC02aaA39b223 \| r:FE8D0A0e5C4F27 \| r:eAD9083C756Cc2 | ![BUYTOK](scenario-5s/14-buytok-p0.png) |
| 15 | `BUYAMT` | 1 | id=BUYAMT lab="BUY MIN" cap="" \| r:0x0000000000000000000000 \| r:0000000000000000000000 \| r:000006f05b59d3b20000 | ![BUYAMT](scenario-5s/15-buyamt-p0.png) |
| 16 | `RECEIVER` | 1 | id=RECEIVER lab="RECEIVER" cap="" \| r:= the Safe | ![RECEIVER](scenario-5s/16-receiver-p0.png) |
| 17 | `EXPIRES` | 1 | id=EXPIRES lab="EXPIRES" cap="" \| r:unix 1744830464 \| r:Partial: no | ![EXPIRES](scenario-5s/17-expires-p0.png) |
| 18 | `FEE` | 1 | id=FEE lab="FEE (SELL)" cap="" \| r:0 units | ![FEE](scenario-5s/18-fee-p0.png) |
| 19 | `SOURCES` | 1 | id=SOURCES lab="SOURCES" cap="" \| r:sell: erc20 \| r:buy: erc20 | ![SOURCES](scenario-5s/19-sources-p0.png) |
| 20 | `APPDATA` | 1 | id=APPDATA lab="APP DATA" cap="" \| r:0x0000000000000000 \| r:0000000000000000 | ![APPDATA](scenario-5s/20-appdata-p0.png) |
| 20 | `APPDATA` | 2 | id=APPDATA lab="APP DATA" cap="" \| r:0000000000000000 \| r:0000000000000000 | ![APPDATA](scenario-5s/20-appdata-p1.png) |
| 21 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5s/21-maxfee-p0.png) |
| 22 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-5s/22-worst-p0.png) |
| 23 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5s/23-signer-p0.png) |
| 24 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0x5AFE000000000000000 \| r:000000000000000000002 | ![TARGET](scenario-5s/24-target-p0.png) |
| 25 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5s/25-gaslane-p0.png) |
| 25 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5s/25-gaslane-p1.png) |
| 26 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5s/26-fp8213-p0.png) |
| 27 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x01760b8c573c5a9b15a4bd \| r:64d44cb09516189a01ba1b \| r:b28f7229e0264e03682c | ![DIGEST](scenario-5s/27-digest-p0.png) |
| 28 | `APPROVE` | 1 | id=APPROVE lab="" cap="APPROVE SAFE TX?" | ![APPROVE](scenario-5s/28-approve-p0.png) |

