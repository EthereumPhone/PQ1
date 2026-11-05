# PQ1 Demo for Ubuntu

The [`macos-demo`](../macos-demo) program on Ubuntu: the [`android-demo`](../android-demo) flows in a
terminal menu, for running PQ1 at a conference booth. Plug in PQ1, unlock it, press a key: PQ1
clear-signs the demo transaction on its own screen. Nothing is broadcast, and signatures never leave
the program. The keys, flows and protocol are described in the
[macOS README](../macos-demo/README.md); the source is the same file,
[`pq1-demo.c`](../macos-demo/pq1-demo.c), so a flow change there reaches both.

It ships as one file, `PQ1 Demo`, a static x86-64 binary with no dependencies. The booth instructions
are in [`README.txt`](README.txt), which ships in the tarball as `Read me.txt`.

## Building

```bash
./build.sh   # needs cc with static glibc (libc6-dev), xxd, tar
```

It embeds the ERC-20 proofs, builds, runs `--selftest` against the Android goldens, and writes
`dist/PQ1 Demo/` and `dist/PQ1-Demo-Ubuntu.tar.gz`. The tarball keeps the executable bit, which a bare
file downloaded by a browser loses.

## What differs from macOS

- **USB permission.** `/dev/hidrawN` is root-only until a udev rule opens it, and no-install is not
  possible here. When PQ1 is on the bus, the open fails with `EACCES` and
  `/etc/udev/rules.d/70-pq1-wallet.rules` is absent, the menu offers `u`, which installs the rule with
  `sudo` in the same window and re-triggers udev. The rule uses `TAG+="uaccess"`: only the user logged
  in at the seat gets access, not every local account. It must sort before `73-seat-late.rules`.
- **Double-click.** The binary's content type is `application/x-executable`, which Files should launch,
  though with no terminal. So with no tty on stdin the program re-runs itself in the first terminal it finds (`gnome-terminal`, `ptyxis`, then others).
  A shell script would not do: Files opens executable text files in the editor.
- **Bounded writes.** A `hidraw` write blocks in the kernel for up to 5 s while PQ1 shows a dialog or
  its PIN prompt and reads no OUT reports. A writer thread does the write and `hid_write` gives up after
  2 s, as on macOS; while that write is stuck, further writes fail at once so the keys stay live.
- **Screen on.** `gnome-session-inhibit` in place of `caffeinate`. It dies with the program
  (`PR_SET_PDEATHSIG`).

## What has been tested

On Ubuntu 24.04: `--selftest`; every path above against a fake PQ1 behind an `LD_PRELOAD` hidraw shim
with UBSan (permission offer, wrong and right password with a stub `sudo`, sign, decline, refuse, a PQ1
that stops reading, lock, unplug); the shipped binary started with no tty (`gnome-terminal` opens at
100x36, inhibitor held, and gone after exit); `udevadm verify` on the rule.

Not yet: a real PQ1, the real `sudo` and udev path on a machine without the rule, a double-click in Files,
and the `ptyxis`, `kgx`, `konsole` and `xfce4-terminal` launchers.

x86-64 only: Ubuntu on Arm PCs would need a second binary from a cross-compiler.
