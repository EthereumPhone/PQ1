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
| 1.0 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-5m-nested/d1-00-rotate-p0.png) |
| 1.1 | `ROTATE` | 1 | id=ROTATE lab="ROTATE" cap="" \| r:New signing slot \| r:Slot 1 | ![ROTATE](scenario-5m-nested/d1-01-rotate-p0.png) |
| 1.2 | `COST` | 1 | id=COST lab="COST" cap="" \| r:+1 bootstrap use \| r:(on-chain cap) | ![COST](scenario-5m-nested/d1-02-cost-p0.png) |
| 1.3 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5m-nested/d1-03-signer-p0.png) |
| 1.4 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5m-nested/d1-04-gaslane-p0.png) |
| 1.4 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5m-nested/d1-04-gaslane-p1.png) |
| 1.5 | `ROTATE` | 1 | id=ROTATE lab="" cap="ROTATE SLOT?" | ![ROTATE](scenario-5m-nested/d1-05-rotate-p0.png) |
| 2.0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN FORWARD CALL?" | ![SIGN](scenario-5m-nested/d2-00-sign-p0.png) |
| 2.1 | `DEV` | 1 | id=DEV lab="! DEV BUILD" cap="" \| r:Unattested \| r:descriptor | ![DEV](scenario-5m-nested/d2-01-dev-p0.png) |
| 2.2 | `INTENT` | 1 | id=INTENT lab="INTENT" cap="" \| s:Forward call \| r:PQSigner \| r:NestedForwarder | ![INTENT](scenario-5m-nested/d2-02-intent-p0.png) |
| 2.3 | `F2` | 1 | id=F2 lab="TARGET" cap="" \| r:0x5656565656565656565 \| r:656565656565656565656 | ![F2](scenario-5m-nested/d2-03-f2-p0.png) |
| 2.4 | `F3` | 1 | id=F3 lab="CALL CALL" cap="" \| r:0x5656565656565656565 \| r:656565656565656565656 | ![F3](scenario-5m-nested/d2-04-f3-p0.png) |
| 2.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5m-nested/d2-05-confirm-p0.png) |
| 2.6 | `F4` | 1 | id=F4 lab="" cap="" \| s:** DEV BUILD ** \| r:Unattested \| r:descriptor | ![F4](scenario-5m-nested/d2-06-f4-p0.png) |
| 2.7 | `F5` | 1 | id=F5 lab="TRANSFER" cap="" \| r:PQSigner \| r:NestedToken | ![F5](scenario-5m-nested/d2-07-f5-p0.png) |
| 2.8 | `F6` | 1 | id=F6 lab="RECIPIENT" cap="" \| r:0x7878787878787878787 \| r:878787878787878787878 | ![F6](scenario-5m-nested/d2-08-f6-p0.png) |
| 2.9 | `F7` | 1 | id=F7 lab="AMOUNT" cap="" \| r:0000000000000000 \| r:0000000000000000 | ![F7](scenario-5m-nested/d2-09-f7-p0.png) |
| 2.9 | `F7` | 2 | id=F7 lab="AMOUNT" cap="" \| r:0000000000000000 \| r:000000000001e240 | ![F7](scenario-5m-nested/d2-09-f7-p1.png) |
| 2.10 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:Chain 31337 | ![NETWORK](scenario-5m-nested/d2-10-network-p0.png) |
| 2.11 | `F10` | 1 | id=F10 lab="MAX FEE/BASE" cap="" \| r:10000000000 \| r:Tip/base: \| r:2000000000 | ![F10](scenario-5m-nested/d2-11-f10-p0.png) |
| 2.12 | `F11` | 1 | id=F11 lab="GAS:450000" cap="" \| r:Max total/base: \| r:4500000000000000 | ![F11](scenario-5m-nested/d2-12-f11-p0.png) |
| 2.13 | `NONCE` | 1 | id=NONCE lab="NONCE (HEX)" cap="" \| r:0000000000000000 \| r:0000000000000000 \| r:0000000000000000 | ![NONCE](scenario-5m-nested/d2-13-nonce-p0.png) |
| 2.13 | `NONCE` | 2 | id=NONCE lab="NONCE (HEX)" cap="" \| r:000000000000002d | ![NONCE](scenario-5m-nested/d2-13-nonce-p1.png) |
| 2.14 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5m-nested/d2-14-signer-p0.png) |
| 2.15 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0x3434343434343434343 \| r:434343434343434343434 | ![TARGET](scenario-5m-nested/d2-15-target-p0.png) |
| 2.16 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5m-nested/d2-16-gaslane-p0.png) |
| 2.16 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5m-nested/d2-16-gaslane-p1.png) |
| 2.17 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5m-nested/d2-17-fp8213-p0.png) |
| 2.18 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x656ac999bd3392b7aa674b \| r:1ae24ca0e5ef17b0f00544 \| r:6ea86edb49ad633e6f12 | ![DIGEST](scenario-5m-nested/d2-18-digest-p0.png) |
| 2.19 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN FORWARD CALL?" | ![SIGN](scenario-5m-nested/d2-19-sign-p0.png) |

## Scenario 5m-multi-tail: ERC-7730 two-string tails match + signs

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN ANNOTATE?" | ![SIGN](scenario-5m-multi-tail/00-sign-p0.png) |
| 1 | `DEV` | 1 | id=DEV lab="! DEV BUILD" cap="" \| r:Unattested \| r:descriptor | ![DEV](scenario-5m-multi-tail/01-dev-p0.png) |
| 2 | `INTENT` | 1 | id=INTENT lab="INTENT" cap="" \| s:Annotate \| r:PQSigner \| r:MultiTailNotes | ![INTENT](scenario-5m-multi-tail/02-intent-p0.png) |
| 3 | `F2` | 1 | id=F2 lab="SUBJECT" cap="" \| r:alpha subject \| r:13 bytes | ![F2](scenario-5m-multi-tail/03-f2-p0.png) |
| 4 | `F3` | 1 | id=F3 lab="MEMO" cap="" \| r:exact memo \| r:10 bytes | ![F3](scenario-5m-multi-tail/04-f3-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5m-multi-tail/05-confirm-p0.png) |
| 6 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:Chain 31337 | ![NETWORK](scenario-5m-multi-tail/06-network-p0.png) |
| 7 | `F5` | 1 | id=F5 lab="MAX FEE/BASE" cap="" \| r:10000000000 \| r:Tip/base: \| r:2000000000 | ![F5](scenario-5m-multi-tail/07-f5-p0.png) |
| 8 | `F6` | 1 | id=F6 lab="GAS:450000" cap="" \| r:Max total/base: \| r:4500000000000000 | ![F6](scenario-5m-multi-tail/08-f6-p0.png) |
| 9 | `NONCE` | 1 | id=NONCE lab="NONCE (HEX)" cap="" \| r:0000000000000000 \| r:0000000000000000 \| r:0000000000000000 | ![NONCE](scenario-5m-multi-tail/09-nonce-p0.png) |
| 9 | `NONCE` | 2 | id=NONCE lab="NONCE (HEX)" cap="" \| r:000000000000002d | ![NONCE](scenario-5m-multi-tail/09-nonce-p1.png) |
| 10 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5m-multi-tail/10-signer-p0.png) |
| 11 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0x7878787878787878787 \| r:878787878787878787878 | ![TARGET](scenario-5m-multi-tail/11-target-p0.png) |
| 12 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5m-multi-tail/12-gaslane-p0.png) |
| 12 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5m-multi-tail/12-gaslane-p1.png) |
| 13 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5m-multi-tail/13-fp8213-p0.png) |
| 14 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0xd9baf3cf86728a714a6db2 \| r:05d884da6658c1c5657384 \| r:1f2f62d2967823331588 | ![DIGEST](scenario-5m-multi-tail/14-digest-p0.png) |
| 15 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN ANNOTATE?" | ![SIGN](scenario-5m-multi-tail/15-sign-p0.png) |

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

## Scenario 5e: atomic batch sign (3 inner txs)

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 1.0 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.100000 ETH?" | ![SEND](scenario-5e/d1-00-send-p0.png) |
| 1.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| s:BATCH SIGN \| r:Tx 1 of 3 | ![BATCH](scenario-5e/d1-01-batch-p0.png) |
| 1.2 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5e/d1-02-network-p0.png) |
| 1.3 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xA0a0a0A0A0A0a0a0A0A \| r:0a0A0a0A0a0A0A0A0a0a0 | ![TO](scenario-5e/d1-03-to-p0.png) |
| 1.4 | `VALUE` | 1 | id=VALUE lab="VALUE" cap="" \| r:0.100000 ETH | ![VALUE](scenario-5e/d1-04-value-p0.png) |
| 1.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5e/d1-05-confirm-p0.png) |
| 1.6 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5e/d1-06-maxfee-p0.png) |
| 1.7 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0058 ETH \| r:(gas: 580000) | ![WORST](scenario-5e/d1-07-worst-p0.png) |
| 1.8 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 8 \| r:Data: 0 B | ![DETAILS](scenario-5e/d1-08-details-p0.png) |
| 1.9 | `NATIVE` | 1 | id=NATIVE lab="NATIVE VALUE" cap="" \| r:! NATIVE ETH \| r:0.100000 ETH | ![NATIVE](scenario-5e/d1-09-native-p0.png) |
| 1.10 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5e/d1-10-signer-p0.png) |
| 1.11 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xA0a0a0A0A0A0a0a0A0A \| r:0a0A0a0A0a0A0A0A0a0a0 | ![TARGET](scenario-5e/d1-11-target-p0.png) |
| 1.12 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5e/d1-12-gaslane-p0.png) |
| 1.12 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5e/d1-12-gaslane-p1.png) |
| 1.13 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5e/d1-13-fp8213-p0.png) |
| 1.14 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x290decd9548b62a8d60345 \| r:a988386fc84ba6bc954840 \| r:08f6362f93160ef3e563 | ![DIGEST](scenario-5e/d1-14-digest-p0.png) |
| 1.15 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.100000 ETH?" | ![SEND](scenario-5e/d1-15-send-p0.png) |
| 2.0 | `TRANSFER` | 1 | id=TRANSFER lab="" cap="TRANSFER UNKNOWN TOKEN?" | ![TRANSFER](scenario-5e/d2-00-transfer-p0.png) |
| 2.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| s:BATCH SIGN \| r:Tx 2 of 3 | ![BATCH](scenario-5e/d2-01-batch-p0.png) |
| 2.2 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5e/d2-02-network-p0.png) |
| 2.3 | `CONTRACT` | 1 | id=CONTRACT lab="CONTRACT" cap="" \| s:! Unknown token \| r:0xA1A1a1a1A1A1A1A1A1a \| r:1a1a1a1a1A1A1a1A1a1a1 | ![CONTRACT](scenario-5e/d2-03-contract-p0.png) |
| 2.4 | `AMOUNT` | 1 | id=AMOUNT lab="AMOUNT" cap="" \| r:(RAW) transfer \| r:250000000 | ![AMOUNT](scenario-5e/d2-04-amount-p0.png) |
| 2.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5e/d2-05-confirm-p0.png) |
| 2.6 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xABaBaBaBABab \| r:ABabAbAbABAbAB \| r:abababaBaBABaB | ![TO](scenario-5e/d2-06-to-p0.png) |
| 2.7 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5e/d2-07-maxfee-p0.png) |
| 2.8 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0058 ETH \| r:(gas: 580000) | ![WORST](scenario-5e/d2-08-worst-p0.png) |
| 2.9 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 8 \| r:Data: 68 B | ![DETAILS](scenario-5e/d2-09-details-p0.png) |
| 2.10 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5e/d2-10-signer-p0.png) |
| 2.11 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xA1A1a1a1A1A1A1A1A1a \| r:1a1a1a1a1A1A1a1A1a1a1 | ![TARGET](scenario-5e/d2-11-target-p0.png) |
| 2.12 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5e/d2-12-gaslane-p0.png) |
| 2.12 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5e/d2-12-gaslane-p1.png) |
| 2.13 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5e/d2-13-fp8213-p0.png) |
| 2.14 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x80abe80e197e36fff456e8 \| r:985f29f9f4f0fa3432afb0 \| r:8f38a8a92f410446a003 | ![DIGEST](scenario-5e/d2-14-digest-p0.png) |
| 2.15 | `TRANSFER` | 1 | id=TRANSFER lab="" cap="TRANSFER UNKNOWN TOKEN?" | ![TRANSFER](scenario-5e/d2-15-transfer-p0.png) |
| 3.0 | `UNKNOWN` | 1 | id=UNKNOWN lab="" cap="CONFIRM UNKNOWN CALL?" | ![UNKNOWN](scenario-5e/d3-00-unknown-p0.png) |
| 3.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| s:BATCH SIGN \| r:Tx 3 of 3 | ![BATCH](scenario-5e/d3-01-batch-p0.png) |
| 3.2 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5e/d3-02-network-p0.png) |
| 3.3 | `BLINDSGN` | 1 | id=BLINDSGN lab="BLIND SIGN" cap="" \| r:Unknown call \| r:Verify on dapp | ![BLINDSGN](scenario-5e/d3-03-blindsgn-p0.png) |
| 3.4 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xa2A2a2A2A2A2A2a2a2a \| r:2a2A2A2A2A2a2A2A2a2a2 | ![TO](scenario-5e/d3-04-to-p0.png) |
| 3.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5e/d3-05-confirm-p0.png) |
| 3.6 | `AMOUNT` | 1 | id=AMOUNT lab="AMOUNT" cap="" \| r:0 ETH | ![AMOUNT](scenario-5e/d3-06-amount-p0.png) |
| 3.7 | `CALLDATA` | 1 | id=CALLDATA lab="CALL DATA" cap="" \| r:Selector: 0x12345678 \| r:Data: 9 B | ![CALLDATA](scenario-5e/d3-07-calldata-p0.png) |
| 3.8 | `DATAHASH` | 1 | id=DATAHASH lab="DATA HASH" cap="" \| r:0x69f98b03597fd56be5fc3b \| r:54a5fd0e67efc7b9c93cc0 \| r:3cd5130ea7019af14fe9 | ![DATAHASH](scenario-5e/d3-08-datahash-p0.png) |
| 3.9 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5e/d3-09-maxfee-p0.png) |
| 3.10 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0058 ETH \| r:(gas: 580000) | ![WORST](scenario-5e/d3-10-worst-p0.png) |
| 3.11 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 8 \| r:Data: 9 B | ![DETAILS](scenario-5e/d3-11-details-p0.png) |
| 3.12 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5e/d3-12-signer-p0.png) |
| 3.13 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xa2A2a2A2A2A2A2a2a2a \| r:2a2A2A2A2A2a2A2A2a2a2 | ![TARGET](scenario-5e/d3-13-target-p0.png) |
| 3.14 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5e/d3-14-gaslane-p0.png) |
| 3.14 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5e/d3-14-gaslane-p1.png) |
| 3.15 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5e/d3-15-fp8213-p0.png) |
| 3.16 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x50d527cb697bd53269541b \| r:f85d48da0823f09d8bcab1 \| r:f1af2369d29c34ab9949 | ![DIGEST](scenario-5e/d3-16-digest-p0.png) |
| 3.17 | `UNKNOWN` | 1 | id=UNKNOWN lab="" cap="CONFIRM UNKNOWN CALL?" | ![UNKNOWN](scenario-5e/d3-17-unknown-p0.png) |
| 4.0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN 3 TXS?" | ![SIGN](scenario-5e/d4-00-sign-p0.png) |
| 4.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| r:Txs in batch: 3 \| r:each confirmed \| r:one signature | ![BATCH](scenario-5e/d4-01-batch-p0.png) |
| 4.2 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5e/d4-02-signer-p0.png) |
| 4.3 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5e/d4-03-gaslane-p0.png) |
| 4.3 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5e/d4-03-gaslane-p1.png) |
| 4.4 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:Raw32 Hash | ![FP8213](scenario-5e/d4-04-fp8213-p0.png) |
| 4.5 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0xf5ba42bd33eb7ea1e60b54 \| r:73d8bdc5be937ed200995c \| r:41855bbfffcf4b53b68f | ![DIGEST](scenario-5e/d4-05-digest-p0.png) |
| 4.6 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN 3 TXS?" | ![SIGN](scenario-5e/d4-06-sign-p0.png) |

## Scenario 5e-7730: batch ERC-7730 trailer matches + signs

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 1.0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN WRAP?" | ![SIGN](scenario-5e-7730/d1-00-sign-p0.png) |
| 1.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| s:BATCH SIGN \| r:Tx 1 of 1 | ![BATCH](scenario-5e-7730/d1-01-batch-p0.png) |
| 1.2 | `DEV` | 1 | id=DEV lab="! DEV BUILD" cap="" \| r:Unattested \| r:descriptor | ![DEV](scenario-5e-7730/d1-02-dev-p0.png) |
| 1.3 | `INTENT` | 1 | id=INTENT lab="INTENT" cap="" \| s:Wrap \| r:WETH \| r:WETH | ![INTENT](scenario-5e-7730/d1-03-intent-p0.png) |
| 1.4 | `F2` | 1 | id=F2 lab="AMOUNT" cap="" \| r:0.01 ETH | ![F2](scenario-5e-7730/d1-04-f2-p0.png) |
| 1.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5e-7730/d1-05-confirm-p0.png) |
| 1.6 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5e-7730/d1-06-network-p0.png) |
| 1.7 | `F4` | 1 | id=F4 lab="MAX FEE/GWEI" cap="" \| r:10 \| r:Tip/gwei: \| r:2 | ![F4](scenario-5e-7730/d1-07-f4-p0.png) |
| 1.8 | `F5` | 1 | id=F5 lab="" cap="" \| s:Max total/ETH: \| r:0.0058 \| r:Gas:580000 | ![F5](scenario-5e-7730/d1-08-f5-p0.png) |
| 1.9 | `NONCE` | 1 | id=NONCE lab="NONCE (HEX)" cap="" \| r:0000000000000000 \| r:0000000000000000 \| r:0000000000000000 | ![NONCE](scenario-5e-7730/d1-09-nonce-p0.png) |
| 1.9 | `NONCE` | 2 | id=NONCE lab="NONCE (HEX)" cap="" \| r:0000000000000051 | ![NONCE](scenario-5e-7730/d1-09-nonce-p1.png) |
| 1.10 | `NATIVE` | 1 | id=NATIVE lab="NATIVE VALUE" cap="" \| r:! NATIVE ETH \| r:0.010000 ETH | ![NATIVE](scenario-5e-7730/d1-10-native-p0.png) |
| 1.11 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5e-7730/d1-11-signer-p0.png) |
| 1.12 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xfFf9976782d46CC0563 \| r:0D1f6eBAb18b2324d6B14 | ![TARGET](scenario-5e-7730/d1-12-target-p0.png) |
| 1.13 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5e-7730/d1-13-gaslane-p0.png) |
| 1.13 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5e-7730/d1-13-gaslane-p1.png) |
| 1.14 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5e-7730/d1-14-fp8213-p0.png) |
| 1.15 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x9e0e1b38823d3ef404d2bf \| r:8305dbf9a8d25df6806279 \| r:99452c844afce8db8319 | ![DIGEST](scenario-5e-7730/d1-15-digest-p0.png) |
| 1.16 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN WRAP?" | ![SIGN](scenario-5e-7730/d1-16-sign-p0.png) |
| 2.0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN 1 TXS?" | ![SIGN](scenario-5e-7730/d2-00-sign-p0.png) |
| 2.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| r:Txs in batch: 1 \| r:each confirmed \| r:one signature | ![BATCH](scenario-5e-7730/d2-01-batch-p0.png) |
| 2.2 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5e-7730/d2-02-signer-p0.png) |
| 2.3 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5e-7730/d2-03-gaslane-p0.png) |
| 2.3 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5e-7730/d2-03-gaslane-p1.png) |
| 2.4 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:Raw32 Hash | ![FP8213](scenario-5e-7730/d2-04-fp8213-p0.png) |
| 2.5 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0xf15966fd0b079a995e7eba \| r:c8e84108ec6066be280bb2 \| r:7d911b813154d3007931 | ![DIGEST](scenario-5e-7730/d2-05-digest-p0.png) |
| 2.6 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN 1 TXS?" | ![SIGN](scenario-5e-7730/d2-06-sign-p0.png) |

## Scenario 5e-rt-erc20: invalid Safe cannot gate ERC-7730 token metadata

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 1.0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN DEPOSIT COLLATERAL?" | ![SIGN](scenario-5e-rt-erc20/d1-00-sign-p0.png) |
| 1.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| s:BATCH SIGN \| r:Tx 1 of 2 | ![BATCH](scenario-5e-rt-erc20/d1-01-batch-p0.png) |
| 1.2 | `DEV` | 1 | id=DEV lab="! DEV BUILD" cap="" \| r:Unattested \| r:descriptor | ![DEV](scenario-5e-rt-erc20/d1-02-dev-p0.png) |
| 1.3 | `INTENT` | 1 | id=INTENT lab="INTENT" cap="" \| s:Deposit collateral \| r:PositionsManage | ![INTENT](scenario-5e-rt-erc20/d1-03-intent-p0.png) |
| 1.4 | `F2` | 1 | id=F2 lab="AMOUNT" cap="" \| r:100 USDT | ![F2](scenario-5e-rt-erc20/d1-04-f2-p0.png) |
| 1.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5e-rt-erc20/d1-05-confirm-p0.png) |
| 1.6 | `F3` | 1 | id=F3 lab="" cap="" \| s:Token contract \| r:0x1CDD2EaB61112697626 \| r:F7b4bB0e23Da4FeBF7B7C | ![F3](scenario-5e-rt-erc20/d1-06-f3-p0.png) |
| 1.7 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Mainnet | ![NETWORK](scenario-5e-rt-erc20/d1-07-network-p0.png) |
| 1.8 | `F5` | 1 | id=F5 lab="MAX FEE/GWEI" cap="" \| r:10 \| r:Tip/gwei: \| r:2 | ![F5](scenario-5e-rt-erc20/d1-08-f5-p0.png) |
| 1.9 | `F6` | 1 | id=F6 lab="" cap="" \| s:Max total/ETH: \| r:0.0058 \| r:Gas:580000 | ![F6](scenario-5e-rt-erc20/d1-09-f6-p0.png) |
| 1.10 | `NONCE` | 1 | id=NONCE lab="NONCE (HEX)" cap="" \| r:0000000000000000 \| r:0000000000000000 \| r:0000000000000000 | ![NONCE](scenario-5e-rt-erc20/d1-10-nonce-p0.png) |
| 1.10 | `NONCE` | 2 | id=NONCE lab="NONCE (HEX)" cap="" \| r:0000000000000053 | ![NONCE](scenario-5e-rt-erc20/d1-10-nonce-p1.png) |
| 1.11 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5e-rt-erc20/d1-11-signer-p0.png) |
| 1.12 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xbe4050a73a7Fb384c65 \| r:E885a15C33461A4B20055 | ![TARGET](scenario-5e-rt-erc20/d1-12-target-p0.png) |
| 1.13 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5e-rt-erc20/d1-13-gaslane-p0.png) |
| 1.13 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5e-rt-erc20/d1-13-gaslane-p1.png) |
| 1.14 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5e-rt-erc20/d1-14-fp8213-p0.png) |
| 1.15 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x55fea8fa20d61df0015cfb \| r:2209e72846a391a1fbce11 \| r:20398e4f71abe9efc133 | ![DIGEST](scenario-5e-rt-erc20/d1-15-digest-p0.png) |
| 1.16 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN DEPOSIT COLLATERAL?" | ![SIGN](scenario-5e-rt-erc20/d1-16-sign-p0.png) |
| 2.0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN DEPOSIT COLLATERAL?" | ![SIGN](scenario-5e-rt-erc20/d2-00-sign-p0.png) |
| 2.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| s:BATCH SIGN \| r:Tx 2 of 2 | ![BATCH](scenario-5e-rt-erc20/d2-01-batch-p0.png) |
| 2.2 | `DEV` | 1 | id=DEV lab="! DEV BUILD" cap="" \| r:Unattested \| r:descriptor | ![DEV](scenario-5e-rt-erc20/d2-02-dev-p0.png) |
| 2.3 | `INTENT` | 1 | id=INTENT lab="INTENT" cap="" \| s:Deposit collateral \| r:PositionsManage | ![INTENT](scenario-5e-rt-erc20/d2-03-intent-p0.png) |
| 2.4 | `F2` | 1 | id=F2 lab="AMOUNT" cap="" \| r:100 USDT | ![F2](scenario-5e-rt-erc20/d2-04-f2-p0.png) |
| 2.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5e-rt-erc20/d2-05-confirm-p0.png) |
| 2.6 | `F3` | 1 | id=F3 lab="" cap="" \| s:Token contract \| r:0xdAC17F958D2ee523a22 \| r:06206994597C13D831ec7 | ![F3](scenario-5e-rt-erc20/d2-06-f3-p0.png) |
| 2.7 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Mainnet | ![NETWORK](scenario-5e-rt-erc20/d2-07-network-p0.png) |
| 2.8 | `F5` | 1 | id=F5 lab="MAX FEE/GWEI" cap="" \| r:10 \| r:Tip/gwei: \| r:2 | ![F5](scenario-5e-rt-erc20/d2-08-f5-p0.png) |
| 2.9 | `F6` | 1 | id=F6 lab="" cap="" \| s:Max total/ETH: \| r:0.0058 \| r:Gas:580000 | ![F6](scenario-5e-rt-erc20/d2-09-f6-p0.png) |
| 2.10 | `NONCE` | 1 | id=NONCE lab="NONCE (HEX)" cap="" \| r:0000000000000000 \| r:0000000000000000 \| r:0000000000000000 | ![NONCE](scenario-5e-rt-erc20/d2-10-nonce-p0.png) |
| 2.10 | `NONCE` | 2 | id=NONCE lab="NONCE (HEX)" cap="" \| r:0000000000000053 | ![NONCE](scenario-5e-rt-erc20/d2-10-nonce-p1.png) |
| 2.11 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5e-rt-erc20/d2-11-signer-p0.png) |
| 2.12 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xbe4050a73a7Fb384c65 \| r:E885a15C33461A4B20055 | ![TARGET](scenario-5e-rt-erc20/d2-12-target-p0.png) |
| 2.13 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5e-rt-erc20/d2-13-gaslane-p0.png) |
| 2.13 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5e-rt-erc20/d2-13-gaslane-p1.png) |
| 2.14 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5e-rt-erc20/d2-14-fp8213-p0.png) |
| 2.15 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x7c6995addaedc5a6fe877e \| r:e8d04bc4ccb87091fe736a \| r:fa33cd7face5becf55a7 | ![DIGEST](scenario-5e-rt-erc20/d2-15-digest-p0.png) |
| 2.16 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN DEPOSIT COLLATERAL?" | ![SIGN](scenario-5e-rt-erc20/d2-16-sign-p0.png) |
| 3.0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN 2 TXS?" | ![SIGN](scenario-5e-rt-erc20/d3-00-sign-p0.png) |
| 3.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| r:Txs in batch: 2 \| r:each confirmed \| r:one signature | ![BATCH](scenario-5e-rt-erc20/d3-01-batch-p0.png) |
| 3.2 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5e-rt-erc20/d3-02-signer-p0.png) |
| 3.3 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5e-rt-erc20/d3-03-gaslane-p0.png) |
| 3.3 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5e-rt-erc20/d3-03-gaslane-p1.png) |
| 3.4 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:Raw32 Hash | ![FP8213](scenario-5e-rt-erc20/d3-04-fp8213-p0.png) |
| 3.5 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x6578f34faa792757c2783f \| r:9738f2b3778bd1f417e414 \| r:3375f8b5e5c8fcef99a6 | ![DIGEST](scenario-5e-rt-erc20/d3-05-digest-p0.png) |
| 3.6 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN 2 TXS?" | ![SIGN](scenario-5e-rt-erc20/d3-06-sign-p0.png) |

## Scenario 5f: degenerate 1-tx batch

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 1.0 | `SEND` | 1 | id=SEND lab="" cap="SEND ETH?" | ![SEND](scenario-5f/d1-00-send-p0.png) |
| 1.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| s:BATCH SIGN \| r:Tx 1 of 1 | ![BATCH](scenario-5f/d1-01-batch-p0.png) |
| 1.2 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5f/d1-02-network-p0.png) |
| 1.3 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xB0B0b0B0B0B0 \| r:B0b0B0B0B0b0b0 \| r:b0b0B0b0b0B0B0 | ![TO](scenario-5f/d1-03-to-p0.png) |
| 1.4 | `VALUE` | 1 | id=VALUE lab="VALUE" cap="" \| r:1 wei | ![VALUE](scenario-5f/d1-04-value-p0.png) |
| 1.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5f/d1-05-confirm-p0.png) |
| 1.6 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5f/d1-06-maxfee-p0.png) |
| 1.7 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0058 ETH \| r:(gas: 580000) | ![WORST](scenario-5f/d1-07-worst-p0.png) |
| 1.8 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 9 \| r:Data: 0 B | ![DETAILS](scenario-5f/d1-08-details-p0.png) |
| 1.9 | `NATIVE` | 1 | id=NATIVE lab="NATIVE VALUE" cap="" \| r:! NATIVE ETH \| r:1 \| r:wei | ![NATIVE](scenario-5f/d1-09-native-p0.png) |
| 1.10 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5f/d1-10-signer-p0.png) |
| 1.11 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xB0B0b0B0B0B0 \| r:B0b0B0B0B0b0b0 \| r:b0b0B0b0b0B0B0 | ![TARGET](scenario-5f/d1-11-target-p0.png) |
| 1.12 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5f/d1-12-gaslane-p0.png) |
| 1.12 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5f/d1-12-gaslane-p1.png) |
| 1.13 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5f/d1-13-fp8213-p0.png) |
| 1.14 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x290decd9548b62a8d60345 \| r:a988386fc84ba6bc954840 \| r:08f6362f93160ef3e563 | ![DIGEST](scenario-5f/d1-14-digest-p0.png) |
| 1.15 | `SEND` | 1 | id=SEND lab="" cap="SEND ETH?" | ![SEND](scenario-5f/d1-15-send-p0.png) |
| 2.0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN 1 TXS?" | ![SIGN](scenario-5f/d2-00-sign-p0.png) |
| 2.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| r:Txs in batch: 1 \| r:each confirmed \| r:one signature | ![BATCH](scenario-5f/d2-01-batch-p0.png) |
| 2.2 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5f/d2-02-signer-p0.png) |
| 2.3 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5f/d2-03-gaslane-p0.png) |
| 2.3 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5f/d2-03-gaslane-p1.png) |
| 2.4 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:Raw32 Hash | ![FP8213](scenario-5f/d2-04-fp8213-p0.png) |
| 2.5 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x13bb430379e55c3c8ec8e0 \| r:948c462d9991432ce38607 \| r:c053d4300a418e9cf1b5 | ![DIGEST](scenario-5f/d2-05-digest-p0.png) |
| 2.6 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN 1 TXS?" | ![SIGN](scenario-5f/d2-06-sign-p0.png) |

## Scenario 5g: max-size batch (N=MAX_BATCH_TXS)

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 1.0 | `CALL` | 1 | id=CALL lab="" cap="CONFIRM CONTRACT CALL?" | ![CALL](scenario-5g/d1-00-call-p0.png) |
| 1.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| s:BATCH SIGN \| r:Tx 1 of 4 | ![BATCH](scenario-5g/d1-01-batch-p0.png) |
| 1.2 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5g/d1-02-network-p0.png) |
| 1.3 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xC0C0c0c0C0C0 \| r:c0c0c0C0c0C0C0 \| r:C0C0C0C0C0c0c0 | ![TO](scenario-5g/d1-03-to-p0.png) |
| 1.4 | `VALUE` | 1 | id=VALUE lab="VALUE" cap="" \| r:0.000000 ETH | ![VALUE](scenario-5g/d1-04-value-p0.png) |
| 1.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5g/d1-05-confirm-p0.png) |
| 1.6 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5g/d1-06-maxfee-p0.png) |
| 1.7 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0058 ETH \| r:(gas: 580000) | ![WORST](scenario-5g/d1-07-worst-p0.png) |
| 1.8 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 10 \| r:Data: 0 B | ![DETAILS](scenario-5g/d1-08-details-p0.png) |
| 1.9 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5g/d1-09-signer-p0.png) |
| 1.10 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xC0C0c0c0C0C0 \| r:c0c0c0C0c0C0C0 \| r:C0C0C0C0C0c0c0 | ![TARGET](scenario-5g/d1-10-target-p0.png) |
| 1.11 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5g/d1-11-gaslane-p0.png) |
| 1.11 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5g/d1-11-gaslane-p1.png) |
| 1.12 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5g/d1-12-fp8213-p0.png) |
| 1.13 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x290decd9548b62a8d60345 \| r:a988386fc84ba6bc954840 \| r:08f6362f93160ef3e563 | ![DIGEST](scenario-5g/d1-13-digest-p0.png) |
| 1.14 | `CALL` | 1 | id=CALL lab="" cap="CONFIRM CONTRACT CALL?" | ![CALL](scenario-5g/d1-14-call-p0.png) |
| 2.0 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.000001 ETH?" | ![SEND](scenario-5g/d2-00-send-p0.png) |
| 2.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| s:BATCH SIGN \| r:Tx 2 of 4 | ![BATCH](scenario-5g/d2-01-batch-p0.png) |
| 2.2 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5g/d2-02-network-p0.png) |
| 2.3 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xC1C1c1c1C1C1 \| r:C1c1c1C1C1C1c1 \| r:C1C1C1c1C1c1c1 | ![TO](scenario-5g/d2-03-to-p0.png) |
| 2.4 | `VALUE` | 1 | id=VALUE lab="VALUE" cap="" \| r:0.000001 ETH | ![VALUE](scenario-5g/d2-04-value-p0.png) |
| 2.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5g/d2-05-confirm-p0.png) |
| 2.6 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5g/d2-06-maxfee-p0.png) |
| 2.7 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0058 ETH \| r:(gas: 580000) | ![WORST](scenario-5g/d2-07-worst-p0.png) |
| 2.8 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 10 \| r:Data: 0 B | ![DETAILS](scenario-5g/d2-08-details-p0.png) |
| 2.9 | `NATIVE` | 1 | id=NATIVE lab="NATIVE VALUE" cap="" \| r:! NATIVE ETH \| r:0.000001 ETH | ![NATIVE](scenario-5g/d2-09-native-p0.png) |
| 2.10 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5g/d2-10-signer-p0.png) |
| 2.11 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xC1C1c1c1C1C1 \| r:C1c1c1C1C1C1c1 \| r:C1C1C1c1C1c1c1 | ![TARGET](scenario-5g/d2-11-target-p0.png) |
| 2.12 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5g/d2-12-gaslane-p0.png) |
| 2.12 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5g/d2-12-gaslane-p1.png) |
| 2.13 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5g/d2-13-fp8213-p0.png) |
| 2.14 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x290decd9548b62a8d60345 \| r:a988386fc84ba6bc954840 \| r:08f6362f93160ef3e563 | ![DIGEST](scenario-5g/d2-14-digest-p0.png) |
| 2.15 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.000001 ETH?" | ![SEND](scenario-5g/d2-15-send-p0.png) |
| 3.0 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.000002 ETH?" | ![SEND](scenario-5g/d3-00-send-p0.png) |
| 3.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| s:BATCH SIGN \| r:Tx 3 of 4 | ![BATCH](scenario-5g/d3-01-batch-p0.png) |
| 3.2 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5g/d3-02-network-p0.png) |
| 3.3 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xc2C2C2C2C2C2 \| r:c2c2c2c2C2C2c2 \| r:C2C2C2C2C2c2C2 | ![TO](scenario-5g/d3-03-to-p0.png) |
| 3.4 | `VALUE` | 1 | id=VALUE lab="VALUE" cap="" \| r:0.000002 ETH | ![VALUE](scenario-5g/d3-04-value-p0.png) |
| 3.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5g/d3-05-confirm-p0.png) |
| 3.6 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5g/d3-06-maxfee-p0.png) |
| 3.7 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0058 ETH \| r:(gas: 580000) | ![WORST](scenario-5g/d3-07-worst-p0.png) |
| 3.8 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 10 \| r:Data: 0 B | ![DETAILS](scenario-5g/d3-08-details-p0.png) |
| 3.9 | `NATIVE` | 1 | id=NATIVE lab="NATIVE VALUE" cap="" \| r:! NATIVE ETH \| r:0.000002 ETH | ![NATIVE](scenario-5g/d3-09-native-p0.png) |
| 3.10 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5g/d3-10-signer-p0.png) |
| 3.11 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xc2C2C2C2C2C2 \| r:c2c2c2c2C2C2c2 \| r:C2C2C2C2C2c2C2 | ![TARGET](scenario-5g/d3-11-target-p0.png) |
| 3.12 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5g/d3-12-gaslane-p0.png) |
| 3.12 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5g/d3-12-gaslane-p1.png) |
| 3.13 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5g/d3-13-fp8213-p0.png) |
| 3.14 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x290decd9548b62a8d60345 \| r:a988386fc84ba6bc954840 \| r:08f6362f93160ef3e563 | ![DIGEST](scenario-5g/d3-14-digest-p0.png) |
| 3.15 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.000002 ETH?" | ![SEND](scenario-5g/d3-15-send-p0.png) |
| 4.0 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.000003 ETH?" | ![SEND](scenario-5g/d4-00-send-p0.png) |
| 4.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| s:BATCH SIGN \| r:Tx 4 of 4 | ![BATCH](scenario-5g/d4-01-batch-p0.png) |
| 4.2 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5g/d4-02-network-p0.png) |
| 4.3 | `TO` | 1 | id=TO lab="TO" cap="" \| r:0xc3c3c3c3c3c3 \| r:c3c3c3C3C3c3C3 \| r:C3C3c3C3C3c3c3 | ![TO](scenario-5g/d4-03-to-p0.png) |
| 4.4 | `VALUE` | 1 | id=VALUE lab="VALUE" cap="" \| r:0.000003 ETH | ![VALUE](scenario-5g/d4-04-value-p0.png) |
| 4.5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5g/d4-05-confirm-p0.png) |
| 4.6 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5g/d4-06-maxfee-p0.png) |
| 4.7 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0058 ETH \| r:(gas: 580000) | ![WORST](scenario-5g/d4-07-worst-p0.png) |
| 4.8 | `DETAILS` | 1 | id=DETAILS lab="DETAILS" cap="" \| r:Nonce: 10 \| r:Data: 0 B | ![DETAILS](scenario-5g/d4-08-details-p0.png) |
| 4.9 | `NATIVE` | 1 | id=NATIVE lab="NATIVE VALUE" cap="" \| r:! NATIVE ETH \| r:0.000003 ETH | ![NATIVE](scenario-5g/d4-09-native-p0.png) |
| 4.10 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5g/d4-10-signer-p0.png) |
| 4.11 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xc3c3c3c3c3c3 \| r:c3c3c3C3C3c3C3 \| r:C3C3c3C3C3c3c3 | ![TARGET](scenario-5g/d4-11-target-p0.png) |
| 4.12 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5g/d4-12-gaslane-p0.png) |
| 4.12 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5g/d4-12-gaslane-p1.png) |
| 4.13 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5g/d4-13-fp8213-p0.png) |
| 4.14 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x290decd9548b62a8d60345 \| r:a988386fc84ba6bc954840 \| r:08f6362f93160ef3e563 | ![DIGEST](scenario-5g/d4-14-digest-p0.png) |
| 4.15 | `SEND` | 1 | id=SEND lab="" cap="SEND 0.000003 ETH?" | ![SEND](scenario-5g/d4-15-send-p0.png) |
| 5.0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN 4 TXS?" | ![SIGN](scenario-5g/d5-00-sign-p0.png) |
| 5.1 | `BATCH` | 1 | id=BATCH lab="BATCH" cap="" \| r:Txs in batch: 4 \| r:each confirmed \| r:one signature | ![BATCH](scenario-5g/d5-01-batch-p0.png) |
| 5.2 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5g/d5-02-signer-p0.png) |
| 5.3 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:60000 \| r:Verify:400000 \| r:PreVer:120000 | ![GASLANE](scenario-5g/d5-03-gaslane-p0.png) |
| 5.3 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:580000 | ![GASLANE](scenario-5g/d5-03-gaslane-p1.png) |
| 5.4 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:Raw32 Hash | ![FP8213](scenario-5g/d5-04-fp8213-p0.png) |
| 5.5 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x1a0bcace677e43cf3f5684 \| r:60c2e9a80e152441c15fa1 \| r:8892c1a98b1501676c2f | ![DIGEST](scenario-5g/d5-05-digest-p0.png) |
| 5.6 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN 4 TXS?" | ![SIGN](scenario-5g/d5-06-sign-p0.png) |

## Scenario 5m: ERC-7730 trailer matches + signs

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN WRAP?" | ![SIGN](scenario-5m/00-sign-p0.png) |
| 1 | `DEV` | 1 | id=DEV lab="! DEV BUILD" cap="" \| r:Unattested \| r:descriptor | ![DEV](scenario-5m/01-dev-p0.png) |
| 2 | `INTENT` | 1 | id=INTENT lab="INTENT" cap="" \| s:Wrap \| r:WETH \| r:WETH | ![INTENT](scenario-5m/02-intent-p0.png) |
| 3 | `F2` | 1 | id=F2 lab="AMOUNT" cap="" \| r:0.01 ETH | ![F2](scenario-5m/03-f2-p0.png) |
| 4 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5m/04-network-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5m/05-confirm-p0.png) |
| 6 | `F4` | 1 | id=F4 lab="MAX FEE/GWEI" cap="" \| r:10 \| r:Tip/gwei: \| r:2 | ![F4](scenario-5m/06-f4-p0.png) |
| 7 | `F5` | 1 | id=F5 lab="" cap="" \| s:Max total/ETH: \| r:0.0045 \| r:Gas:450000 | ![F5](scenario-5m/07-f5-p0.png) |
| 8 | `NONCE` | 1 | id=NONCE lab="NONCE (HEX)" cap="" \| r:0000000000000000 \| r:0000000000000000 \| r:0000000000000000 | ![NONCE](scenario-5m/08-nonce-p0.png) |
| 8 | `NONCE` | 2 | id=NONCE lab="NONCE (HEX)" cap="" \| r:000000000000002a | ![NONCE](scenario-5m/08-nonce-p1.png) |
| 9 | `NATIVE` | 1 | id=NATIVE lab="NATIVE VALUE" cap="" \| r:! NATIVE ETH \| r:0.010000 ETH | ![NATIVE](scenario-5m/09-native-p0.png) |
| 10 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5m/10-signer-p0.png) |
| 11 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0xfFf9976782d46CC0563 \| r:0D1f6eBAb18b2324d6B14 | ![TARGET](scenario-5m/11-target-p0.png) |
| 12 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5m/12-gaslane-p0.png) |
| 12 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5m/12-gaslane-p1.png) |
| 13 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5m/13-fp8213-p0.png) |
| 14 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x9e0e1b38823d3ef404d2bf \| r:8305dbf9a8d25df6806279 \| r:99452c844afce8db8319 | ![DIGEST](scenario-5m/14-digest-p0.png) |
| 15 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN WRAP?" | ![SIGN](scenario-5m/15-sign-p0.png) |

## Scenario 5p: EIP-712 typed sign + binding differential

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN DELEGATE?" | ![SIGN](scenario-5p/00-sign-p0.png) |
| 1 | `DEV` | 1 | id=DEV lab="! DEV BUILD" cap="" \| r:Unattested \| r:descriptor | ![DEV](scenario-5p/01-dev-p0.png) |
| 2 | `INTENT` | 1 | id=INTENT lab="INTENT" cap="" \| s:Delegate \| r:PQSigner \| r:E2E Delegate | ![INTENT](scenario-5p/02-intent-p0.png) |
| 3 | `F2` | 1 | id=F2 lab="DELEGATEE" cap="" \| r:0x4242424242424242424 \| r:242424242424242424242 | ![F2](scenario-5p/03-f2-p0.png) |
| 4 | `F3` | 1 | id=F3 lab="NONCE" cap="" \| r:0000000000000000 \| r:0000000000000000 | ![F3](scenario-5p/04-f3-p0.png) |
| 4 | `F3` | 2 | id=F3 lab="NONCE" cap="" \| r:0000000000000000 \| r:0000000000000007 | ![F3](scenario-5p/04-f3-p1.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5p/05-confirm-p0.png) |
| 6 | `F5` | 1 | id=F5 lab="EXPIRY" cap="" \| r:0000000000000000 \| r:0000000000000000 | ![F5](scenario-5p/06-f5-p0.png) |
| 6 | `F5` | 2 | id=F5 lab="EXPIRY" cap="" \| r:0000000000000000 \| r:0000000077359400 | ![F5](scenario-5p/06-f5-p1.png) |
| 7 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5p/07-network-p0.png) |
| 8 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:EIP-712 Final | ![FP8213](scenario-5p/08-fp8213-p0.png) |
| 9 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0xea57cad152799a4828cc58 \| r:866ebd967a28c63b836c79 \| r:88c373a904ded022e9ed | ![DIGEST](scenario-5p/09-digest-p0.png) |
| 10 | `OFFSIGNR` | 1 | id=OFFSIGNR lab="ACCOUNT" cap="" \| r:Account: 0 \| r:Slot: 1 | ![OFFSIGNR](scenario-5p/10-offsignr-p0.png) |
| 11 | `WALLET` | 1 | id=WALLET lab="WALLET" cap="" \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![WALLET](scenario-5p/11-wallet-p0.png) |
| 12 | `MODE` | 1 | id=MODE lab="MODE" cap="" \| r:DEPLOYED EIP1271 \| r:Use 1/65536 \| r:Gap: 1 | ![MODE](scenario-5p/12-mode-p0.png) |
| 13 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN DELEGATE?" | ![SIGN](scenario-5p/13-sign-p0.png) |

## Scenario 5p-personal: personal_sign off-chain signature

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN EIP-1271?" | ![SIGN](scenario-5p-personal/00-sign-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5p-personal/01-network-p0.png) |
| 2 | `MODE` | 1 | id=MODE lab="DETAILS" cap="" \| r:Account contract \| r:is deployed \| r:Verify on dapp | ![MODE](scenario-5p-personal/02-mode-p0.png) |
| 3 | `ACCOUNT` | 1 | id=ACCOUNT lab="ACCOUNT" cap="" \| r:Account: 0 \| r:Slot: 1 | ![ACCOUNT](scenario-5p-personal/03-account-p0.png) |
| 4 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5p-personal/04-signer-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5p-personal/05-confirm-p0.png) |
| 6 | `MSG` | 1 | id=MSG lab="MESSAGE" cap="" \| r:Login to app.example. \| r:com? Nonce: \| r:8f3a9c2e1b | ![MSG](scenario-5p-personal/06-msg-p0.png) |
| 7 | `KEYS` | 1 | id=KEYS lab="KEYS" cap="" \| r:2/65536 keys used \| r:Gap: 2 | ![KEYS](scenario-5p-personal/07-keys-p0.png) |
| 8 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5p-personal/08-fp8213-p0.png) |
| 9 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0xa72199a4ddd6ba427bb621 \| r:6846cb41412c6c5fcdaffe \| r:53454d121bacefb42a98 | ![DIGEST](scenario-5p-personal/09-digest-p0.png) |
| 10 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN EIP-1271?" | ![SIGN](scenario-5p-personal/10-sign-p0.png) |

## Scenario 5p-raw32: RAW32 off-chain signature

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN BLIND HASH?" | ![SIGN](scenario-5p-raw32/00-sign-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5p-raw32/01-network-p0.png) |
| 2 | `BLIND` | 1 | id=BLIND lab="BLIND" cap="" \| s:! BLIND RAW32 \| r:Hash only, no text \| r:Check it on the dapp | ![BLIND](scenario-5p-raw32/02-blind-p0.png) |
| 3 | `MODE` | 1 | id=MODE lab="DETAILS" cap="" \| r:Account contract \| r:is deployed \| r:Verify on dapp | ![MODE](scenario-5p-raw32/03-mode-p0.png) |
| 4 | `ACCOUNT` | 1 | id=ACCOUNT lab="ACCOUNT" cap="" \| r:Account: 0 \| r:Slot: 1 | ![ACCOUNT](scenario-5p-raw32/04-account-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5p-raw32/05-confirm-p0.png) |
| 6 | `HASH` | 1 | id=HASH lab="HASH" cap="" \| r:0x7d7d7d7d7d7d7d7d7d7d7d \| r:7d7d7d7d7d7d7d7d7d7d7d \| r:7d7d7d7d7d7d7d7d7d7d | ![HASH](scenario-5p-raw32/06-hash-p0.png) |
| 7 | `KEYS` | 1 | id=KEYS lab="KEYS" cap="" \| r:3/65536 keys used \| r:Gap: 3 | ![KEYS](scenario-5p-raw32/07-keys-p0.png) |
| 8 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:Raw32 Hash | ![FP8213](scenario-5p-raw32/08-fp8213-p0.png) |
| 9 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x7d7d7d7d7d7d7d7d7d7d7d \| r:7d7d7d7d7d7d7d7d7d7d7d \| r:7d7d7d7d7d7d7d7d7d7d | ![DIGEST](scenario-5p-raw32/09-digest-p0.png) |
| 10 | `FP8213B` | 1 | id=FP8213B lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:ReplaySafe Hash | ![FP8213B](scenario-5p-raw32/10-fp8213b-p0.png) |
| 11 | `DIGEST2` | 1 | id=DIGEST2 lab="DIGEST" cap="" \| r:0xe73b69fffa2632cdf49b8f \| r:e320b4dc2c4ff98b0132c2 \| r:8395360b7d8f9d63ee65 | ![DIGEST2](scenario-5p-raw32/11-digest2-p0.png) |
| 12 | `OFFSIGNR` | 1 | id=OFFSIGNR lab="ACCOUNT" cap="" \| r:Account: 0 \| r:Slot: 1 | ![OFFSIGNR](scenario-5p-raw32/12-offsignr-p0.png) |
| 13 | `WALLET` | 1 | id=WALLET lab="WALLET" cap="" \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![WALLET](scenario-5p-raw32/13-wallet-p0.png) |
| 14 | `MODE` | 1 | id=MODE lab="MODE" cap="" \| r:DEPLOYED EIP1271 \| r:Use 3/65536 \| r:Gap: 3 | ![MODE](scenario-5p-raw32/14-mode-p0.png) |
| 15 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN BLIND HASH?" | ![SIGN](scenario-5p-raw32/15-sign-p0.png) |

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

## Scenario 5q-direct: direct CoW order clear-sign

| # | id | page | record text | frame |
|---|----|------|-------------|-------|
| 0 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN COWSWAP?" | ![SIGN](scenario-5q-direct/00-sign-p0.png) |
| 1 | `NETWORK` | 1 | id=NETWORK lab="" cap="" \| r:on Sepolia | ![NETWORK](scenario-5q-direct/01-network-p0.png) |
| 2 | `ORDER` | 1 | id=ORDER lab="ORDER" cap="" \| r:SELL order | ![ORDER](scenario-5q-direct/02-order-p0.png) |
| 3 | `SELLTOK` | 1 | id=SELLTOK lab="SELL TOKEN" cap="" \| r:0xC02aaA39b223 \| r:FE8D0A0e5C4F27 \| r:eAD9083C756Cc2 | ![SELLTOK](scenario-5q-direct/03-selltok-p0.png) |
| 4 | `SELLAMT` | 1 | id=SELLAMT lab="SELL" cap="" \| r:0x0000000000000000000000 \| r:0000000000000000000000 \| r:000006f05b59d3b20000 | ![SELLAMT](scenario-5q-direct/04-sellamt-p0.png) |
| 5 | `CONFIRM` | 1 | id=CONFIRM lab="" cap="CONFIRM?" | ![CONFIRM](scenario-5q-direct/05-confirm-p0.png) |
| 6 | `BUYTOK` | 1 | id=BUYTOK lab="BUY TOKEN" cap="" \| r:0xA0b86991c6218b36c1d \| r:19D4a2e9Eb0cE3606eB48 | ![BUYTOK](scenario-5q-direct/06-buytok-p0.png) |
| 7 | `BUYAMT` | 1 | id=BUYAMT lab="BUY MIN" cap="" \| r:0x0000000000000000000000 \| r:0000000000000000000000 \| r:0000000000006dcf6b70 | ![BUYAMT](scenario-5q-direct/07-buyamt-p0.png) |
| 8 | `RECEIVER` | 1 | id=RECEIVER lab="RECEIVER" cap="" \| r:0x0000000000000000000 \| r:000000000000000000000 | ![RECEIVER](scenario-5q-direct/08-receiver-p0.png) |
| 9 | `EXPIRES` | 1 | id=EXPIRES lab="EXPIRES" cap="" \| r:unix 1744830464 \| r:Partial: no | ![EXPIRES](scenario-5q-direct/09-expires-p0.png) |
| 10 | `FEE` | 1 | id=FEE lab="FEE (SELL)" cap="" \| r:0 units | ![FEE](scenario-5q-direct/10-fee-p0.png) |
| 11 | `SOURCES` | 1 | id=SOURCES lab="SOURCES" cap="" \| r:sell: erc20 \| r:buy: erc20 | ![SOURCES](scenario-5q-direct/11-sources-p0.png) |
| 12 | `APPDATA` | 1 | id=APPDATA lab="APP DATA" cap="" \| r:0x0000000000000000 \| r:0000000000000000 | ![APPDATA](scenario-5q-direct/12-appdata-p0.png) |
| 12 | `APPDATA` | 2 | id=APPDATA lab="APP DATA" cap="" \| r:0000000000000000 \| r:0000000000000000 | ![APPDATA](scenario-5q-direct/12-appdata-p1.png) |
| 13 | `MAXFEE` | 1 | id=MAXFEE lab="MAX FEE" cap="" \| r:Fees: max / tip \| r:10 gwei \| r:2 gwei | ![MAXFEE](scenario-5q-direct/13-maxfee-p0.png) |
| 14 | `WORST` | 1 | id=WORST lab="WORST CASE" cap="" \| r:Worst-case: \| r:0.0045 ETH \| r:(gas: 450000) | ![WORST](scenario-5q-direct/14-worst-p0.png) |
| 15 | `SIGNER` | 1 | id=SIGNER lab="SIGNER" cap="" \| s:Signer acct #0 \| r:0xBEe6A6E73E418D42eF3 \| r:82ECF8E8025740e97c2fE | ![SIGNER](scenario-5q-direct/15-signer-p0.png) |
| 16 | `TARGET` | 1 | id=TARGET lab="TARGET" cap="" \| r:0x9008D19f58AAbD9eD0D \| r:60971565AA8510560ab41 | ![TARGET](scenario-5q-direct/16-target-p0.png) |
| 17 | `GASLANE` | 1 | id=GASLANE lab="GAS LANE" cap="" \| r:Call:50000 \| r:Verify:300000 \| r:PreVer:100000 | ![GASLANE](scenario-5q-direct/17-gaslane-p0.png) |
| 17 | `GASLANE` | 2 | id=GASLANE lab="GAS LANE" cap="" \| r:Total:450000 | ![GASLANE](scenario-5q-direct/17-gaslane-p1.png) |
| 18 | `FP8213` | 1 | id=FP8213 lab="ERC-8213" cap="" \| r:8213 Fingerprint \| r:CalldataDigest | ![FP8213](scenario-5q-direct/18-fp8213-p0.png) |
| 19 | `DIGEST` | 1 | id=DIGEST lab="DIGEST" cap="" \| r:0x7e2f6fe5267d92010dfdd5 \| r:753ca605616cab88a3c166 \| r:856be86dfb87320f4fd6 | ![DIGEST](scenario-5q-direct/19-digest-p0.png) |
| 20 | `SIGN` | 1 | id=SIGN lab="" cap="SIGN COWSWAP?" | ![SIGN](scenario-5q-direct/20-sign-p0.png) |

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

## Lifecycle: boot (host fixture `pqsigner-ui-px/tests/fixtures/lifecycle/boot.hex`)

| # | id | caption | frame |
|---|----|---------|-------|
| 0 | `SPLASH` | PQ1 | ![SPLASH](lifecycle-boot/00-splash-p0.png) |
| 1 | `OSFPRINT` | OS FINGERPRINT | ![OSFPRINT](lifecycle-boot/01-osfprint-p0.png) |
| 2 | `FPRINT` |  | ![FPRINT](lifecycle-boot/02-fprint-p0.png) |
| 3 | `READY` | READY | ![READY](lifecycle-boot/03-ready-p0.png) |

## Lifecycle: fw_update (host fixture `pqsigner-ui-px/tests/fixtures/lifecycle/fw_update.hex`)

| # | id | caption | frame |
|---|----|---------|-------|
| 0 | `UPDATE` | UPDATE TO V0.1.0.3? | ![UPDATE](lifecycle-fw-update/00-update-p0.png) |
| 1 | `VERSION` |  | ![VERSION](lifecycle-fw-update/01-version-p0.png) |
| 2 | `FWPRINT` |  | ![FWPRINT](lifecycle-fw-update/02-fwprint-p0.png) |
| 3 | `FWWORDS` |  | ![FWWORDS](lifecycle-fw-update/03-fwwords-p0.png) |
| 4 | `KEYPRINT` |  | ![KEYPRINT](lifecycle-fw-update/04-keyprint-p0.png) |
| 5 | `KEYWORDS` |  | ![KEYWORDS](lifecycle-fw-update/05-keywords-p0.png) |
| 6 | `UPDATE` | UPDATE TO V0.1.0.3? | ![UPDATE](lifecycle-fw-update/06-update-p0.png) |

## Lifecycle: fw_verify (host fixture `pqsigner-ui-px/tests/fixtures/lifecycle/fw_verify.hex`)

| # | id | caption | frame |
|---|----|---------|-------|
| 0 | `FWVERIFY` | VERIFY FIRMWARE PACKAGE? | ![FWVERIFY](lifecycle-fw-verify/00-fwverify-p0.png) |
| 1 | `FWMODE` |  | ![FWMODE](lifecycle-fw-verify/01-fwmode-p0.png) |
| 2 | `FWVERIFY` | VERIFY FIRMWARE PACKAGE? | ![FWVERIFY](lifecycle-fw-verify/02-fwverify-p0.png) |

## Lifecycle: offchain_sync (host fixture `pqsigner-ui-px/tests/fixtures/lifecycle/offchain_sync.hex`)

| # | id | caption | frame |
|---|----|---------|-------|
| 0 | `SYNC` | SYNC OFF-CHAIN FLOOR? | ![SYNC](lifecycle-offchain-sync/00-sync-p0.png) |
| 1 | `SYNCNET` |  | ![SYNCNET](lifecycle-offchain-sync/01-syncnet-p0.png) |
| 2 | `SLOT` |  | ![SLOT](lifecycle-offchain-sync/02-slot-p0.png) |
| 3 | `COUNT` |  | ![COUNT](lifecycle-offchain-sync/03-count-p0.png) |
| 4 | `SYNC` | SYNC OFF-CHAIN FLOOR? | ![SYNC](lifecycle-offchain-sync/04-sync-p0.png) |

## Lifecycle: outcomes (host fixture `pqsigner-ui-px/tests/fixtures/lifecycle/outcomes.hex`)

| # | id | caption | frame |
|---|----|---------|-------|
| 0 | `CANCELED` | CANCELED | ![CANCELED](lifecycle-outcomes/00-canceled-p0.png) |
| 1 | `SIGNED` | SIGNED | ![SIGNED](lifecycle-outcomes/01-signed-p0.png) |
| 2 | `WIPING` | WIPING - DO NOT POWER OFF | ![WIPING](lifecycle-outcomes/02-wiping-p0.png) |
| 3 | `WIPED` | WALLET WIPED | ![WIPED](lifecycle-outcomes/03-wiped-p0.png) |
| 4 | `TAMPER` | TAMPER DETECTED | ![TAMPER](lifecycle-outcomes/04-tamper-p0.png) |
| 5 | `RNG` | RNG FAILED | ![RNG](lifecycle-outcomes/05-rng-p0.png) |
| 6 | `FACTORY` | FACTORY SIGNING | ![FACTORY](lifecycle-outcomes/06-factory-p0.png) |
| 7 | `NOTICE` |  | ![NOTICE](lifecycle-outcomes/07-notice-p0.png) |
| 8 | `NOTICE` |  | ![NOTICE](lifecycle-outcomes/08-notice-p0.png) |
| 9 | `BUSY` | PROVISIONING ... | ![BUSY](lifecycle-outcomes/09-busy-p0.png) |
| 10 | `BUSY` | GENERATING KEYS | ![BUSY](lifecycle-outcomes/10-busy-p0.png) |

## Lifecycle: unlock (host fixture `pqsigner-ui-px/tests/fixtures/lifecycle/unlock.hex`)

| # | id | caption | frame |
|---|----|---------|-------|
| 0 | `PIN` | ENTER PIN | ![PIN](lifecycle-unlock/00-pin-p0.png) |
| 1 | `PIN` | ENTER PIN | ![PIN](lifecycle-unlock/01-pin-p0.png) |
| 2 | `CHECKPIN` | CHECKING PIN | ![CHECKPIN](lifecycle-unlock/02-checkpin-p0.png) |
| 3 | `WRONGPIN` | WRONG PIN | ![WRONGPIN](lifecycle-unlock/03-wrongpin-p0.png) |
| 4 | `LASTTRY` | LAST ATTEMPT - WIPES ON FAIL | ![LASTTRY](lifecycle-unlock/04-lasttry-p0.png) |
| 5 | `UNLOCKED` | UNLOCKED | ![UNLOCKED](lifecycle-unlock/05-unlocked-p0.png) |
| 6 | `LOCKED` | LOCKED | ![LOCKED](lifecycle-unlock/06-locked-p0.png) |
| 7 | `PINLOCK` | PIN LOCKED - POWER CYCLE | ![PINLOCK](lifecycle-unlock/07-pinlock-p0.png) |

## Lifecycle: wallet_address (host fixture `pqsigner-ui-px/tests/fixtures/lifecycle/wallet_address.hex`)

| # | id | caption | frame |
|---|----|---------|-------|
| 0 | `WALLET` | CONFIRM ACCOUNT 0 ADDRESS? | ![WALLET](lifecycle-wallet-address/00-wallet-p0.png) |
| 1 | `ADDRESS` |  | ![ADDRESS](lifecycle-wallet-address/01-address-p0.png) |
| 2 | `WALLET` | CONFIRM ACCOUNT 0 ADDRESS? | ![WALLET](lifecycle-wallet-address/02-wallet-p0.png) |

## Lifecycle: wizard (host fixture `pqsigner-ui-px/tests/fixtures/lifecycle/wizard.hex`)

| # | id | caption | frame |
|---|----|---------|-------|
| 0 | `CHOICE` | CREATE NEW WALLET? | ![CHOICE](lifecycle-wizard/00-choice-p0.png) |
| 1 | `CHOICE` | RESTORE WALLET? | ![CHOICE](lifecycle-wizard/01-choice-p0.png) |
| 2 | `PIN` | SET NEW PIN | ![PIN](lifecycle-wizard/02-pin-p0.png) |
| 3 | `WRITE24` | WRITE DOWN 24 WORDS | ![WRITE24](lifecycle-wizard/03-write24-p0.png) |
| 4 | `SEED` |  | ![SEED](lifecycle-wizard/04-seed-p0.png) |
| 5 | `WORD` | CHECK WORD 5 | ![WORD](lifecycle-wizard/05-word-p0.png) |
| 6 | `PICK` | WORD 3 OF 24 | ![PICK](lifecycle-wizard/06-pick-p0.png) |
| 7 | `BACKUPOK` | BACKUP OK | ![BACKUPOK](lifecycle-wizard/07-backupok-p0.png) |
| 8 | `NOMATCH` | NO MATCH | ![NOMATCH](lifecycle-wizard/08-nomatch-p0.png) |
| 9 | `BADSEED` | WRONG SEED PHRASE | ![BADSEED](lifecycle-wizard/09-badseed-p0.png) |
| 10 | `PINDIFF` | PINS DIFFER | ![PINDIFF](lifecycle-wizard/10-pindiff-p0.png) |

