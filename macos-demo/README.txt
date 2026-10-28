PQ1 Demo for macOS
==================

Runs demo transactions on a PQ1 so visitors can watch it clear-sign them on its own screen.
Nothing is broadcast and nothing is installed. Works on Apple Silicon and Intel Macs, macOS 11+.

1. Double-click "PQ1 Demo.command". A Terminal window opens with the demo menu.
2. Plug PQ1 into the Mac with a USB-C cable and enter its PIN on PQ1.
   The menu header turns to "Unlocked" and shows the wallet address.
3. Press a number key. PQ1 shows the transaction:
   both buttons together sign, holding the left button declines.

   1  Safe: USDC payment             4  Send USDC
   2  Safe: CoW swap                 5  Send ETH
   3  Safe: CoW swap, Safe UI batch  6  CoW swap
   7  Bybit hack, replayed: PQ1 refuses it with no confirm screen at all
   a  Show the wallet address on PQ1
   l  Lock PQ1 (the PIN is needed again)

   e  change the amounts and recipients     s  set the Safe address
   r  reset the request counter             q  quit
   Esc  stop waiting / clear the result

   A key pressed while PQ1 shows a request queues that demo; decline on PQ1 to switch.
   If PQ1 locks itself (120 s idle) or is unplugged, the demo runs again once it is unlocked.

If macOS will not open "PQ1 Demo.command"
-----------------------------------------
macOS blocks files from the internet that are not from an identified developer. Any one of:

  * System Settings > Privacy & Security, scroll down, "Open Anyway" next to
    "PQ1 Demo.command", then double-click it again.
  * Or in Terminal, type  bash  and a space, drag "PQ1 Demo.command" into the window, press Enter.
  * Or copy it to the Mac from a USB stick instead of a download or AirDrop.

If it says it cannot be executed: in Terminal, type  chmod +x  and a space, drag the file in,
press Enter.
