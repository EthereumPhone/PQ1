PQ1 Demo for Ubuntu
===================

Runs demo transactions on a PQ1 so visitors can watch it clear-sign them on its own screen.
Nothing is broadcast. Works on Ubuntu 22.04 and newer, on x86-64 PCs (not Arm).

1. Double-click "PQ1 Demo". A terminal window opens with the demo menu.
2. Plug PQ1 into the computer with a USB-C cable and enter its PIN on PQ1.

   The first time on a computer, the menu says "Press u to allow PQ1 on this computer".
   Press u and type your computer password. You need to do this only once.

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

If double-clicking does not start it
------------------------------------
  * Right-click "PQ1 Demo" and choose "Run as a Program".
  * If that is missing: right-click, Properties, turn on "Executable as Program", try again.
  * Or open a terminal, drag "PQ1 Demo" into the window, press Enter.

What it leaves on the computer
------------------------------
  * /etc/udev/rules.d/70-pq1-wallet.rules, the permission from step 2.
    To remove it:  sudo rm /etc/udev/rules.d/70-pq1-wallet.rules
  * ~/.pq1-demo, the request counter and the Safe address.
