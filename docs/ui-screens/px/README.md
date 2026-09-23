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

