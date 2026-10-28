# PQ1 Demo (Android)

A pocket version of the EVT demo scripts (`tools/demo_safe_usdc.py`, `tools/demo_px_flows.py`,
`tools/demo_bybit_replay.py`). Plug an unlocked PQ1 into an Android phone (USB-C to USB-C),
pick a flow, and the device clear-signs it on its own screen.

Flows: Safe USDC payment · Safe CoW swap (presign) · Safe CoW via MultiSendCallOnly v1.5.0 (the
Safe web-UI shape) · Send USDC · Send ETH · direct CoW swap (mainnet) · Bybit hack replay
(PQ1 must refuse) · show address on PQ1 · lock. Amounts and recipients can be edited.

Nothing is broadcast. Signatures stay on the phone.

## Build & install

    ./gradlew :app:assembleDebug
    adb install -r app/build/outputs/apk/debug/app-debug.apk

## Use

Tap a demo. It opens full screen and waits until PQ1 is plugged in and unlocked, then sends the
request. Both buttons sign; holding left declines. Use the chips at the bottom to run the next
demo, or a different one. If you tap another demo while PQ1 is still showing a request, it is
queued: decline the current one on PQ1 (hold left) and the new one starts. If PQ1 relocks or is
unplugged mid-request, the demo waits and runs again after the next unlock. Long-press a demo on
the main list to edit its amounts or recipient.

PQ1 only appears over USB after it is unlocked. When Android asks to open **PQ1 Demo**, tick
"always" so later unlocks connect without asking.

The request counter is the UserOp nonce, and the Safe nonce is 17 + counter, the same as the
Python scripts. Reset it, or set your own Safe address, under `⋯`.

## Keeping it in sync with firmware

- `app/src/main/assets/erc20/*.bin` are ERC-20 Merkle proofs cut from
  `tools/companion-stub/erc20_db.bin`. If the firmware's `ERC20_DB_ROOT` changes, re-run
  `tools/gen_assets.py` and rebuild. Otherwise tokens show as unverified.
- `./gradlew :app:testDebugUnitTest` (`FlowGoldenTest`) checks every request byte for byte
  against the Python demo builders (goldens come from `tools/gen_assets.py`).
- The MultiSend v1.5.0 and Safe-wrapped CoW flows need a firmware with that support (the
  `ui-px-evt` line). `gen_assets.py` reads the ui-px worktree's `demo_px_flows.py` by default.
