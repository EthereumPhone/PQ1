# PQ1 Demo for macOS

The [`android-demo`](../android-demo) flows in a Terminal menu, for running PQ1 at a conference booth on
a Mac. Plug in PQ1, unlock it, press a key: PQ1 clear-signs the demo transaction on its own screen.
Nothing is broadcast, and signatures never leave the program.

It ships as one double-clickable file, `PQ1 Demo.command`. That file is a bash script that carries the
program for both Apple Silicon and Intel Macs, unpacks it into `$TMPDIR` and runs it. It needs no
install, no Xcode, no browser and no admin rights. The booth instructions, including the one-time
Gatekeeper step, are in [`README.txt`](README.txt), which ships in the zip as `Read me.txt`.

## Why not a pure bash script

macOS only reaches a HID device through IOKit's `IOHIDManager`, which needs C callbacks. bash and
`osascript` cannot do that, and Python and Swift are only there once the Xcode tools are installed.
So the program is one C file, [`pq1-demo.c`](pq1-demo.c):

- it links `libSystem` only and loads IOKit and CoreFoundation with `dlopen`;
- `zig cc` cross-compiles it from Linux, with no macOS SDK needed;
- the arm64 binary is ad-hoc signed by zig's linker.

PQ1's HID interface is on the vendor usage page `0xFFA0`, so macOS asks for no Input Monitoring
permission.

## Building

```bash
./build.sh   # needs cc, zig (or ZIG=/path/to/zig), xxd, base64, zip
```

The script:

1. embeds the ERC-20 proof bundles from `android-demo/app/src/main/assets/erc20/`;
2. builds a host binary and runs `--selftest`;
3. cross-builds `aarch64-macos.11.0` and `x86_64-macos.11.0`;
4. writes `dist/PQ1 Demo.command` and `dist/PQ1-Demo-macOS.zip`.

The zip keeps the executable bit, which a bare `.command` downloaded by a browser loses.

`--selftest` builds every flow with `FlowGoldenTest`'s fixed context and requires byte equality
with `android-demo/app/src/test/resources/golden/*.bin`, which come from `tools/demo_px_flows.py`.
It covers the 7 sign requests and the HID framing of a chained block and of `GET_WALLET_ADDRESS`.
So the two demos cannot drift silently:

- when you change a flow in `android-demo/.../core/Flows.kt`, port the change here;
- when `ERC20_DB_ROOT` changes, re-run `android-demo/tools/gen_assets.py`, then `./build.sh`.

The same source builds a Linux binary (`build/pq1-demo`) with a hidraw backend, for trying the demo
against a PQ1 on a Linux bench. It needs the `70-pq1-wallet.rules` udev rule.

## How it talks to PQ1

The protocol is the one in `core/Apdu.kt` and `core/Pq1.kt` (see `docs/companion/usb-protocol-v2.md`):

- APDU v2 in 64-byte HID frames on channel `0x0001`, tag `0x05`;
- requests chained in 255-byte blocks with `P1=0x80`;
- replies drained with `GET_RESPONSE` while SW1 is `0x61`.

Two additions for macOS:

- **Bounded writes.** Every write uses `IOHIDDeviceSetReportWithCallback` with a 2 s timeout. While
  PQ1 shows a dialog or its PIN prompt it reads no OUT reports, and the plain `IOHIDDeviceSetReport`
  would block forever.
- **A PING barrier before every status poll.** PQ1 echoes a tag-`0x02` frame unchanged
  (`shared/src/apdu_framing.rs`). Everything that arrives before the echo of a fresh nonce is
  dropped. A late reply to an abandoned request, or to a write the OS kept queued after its
  timeout, therefore cannot be taken for the next answer.

| Key | |
|---|---|
| `1`–`7` | the demo flows, same titles, defaults and expected results as Android |
| `a` / `l` | show the address on PQ1 / lock PQ1 |
| `e` / `s` / `r` | edit a flow's amounts and recipients / set the Safe address / reset the counter |
| `Esc` / `x` / `q` | stop waiting or clear / drop the queued demo / quit |

The request counter (the UserOp nonce; the Safe nonce is 17 + it) and the Safe address persist in
`~/.pq1-demo`. Edited amounts last until the program quits, as on Android.
