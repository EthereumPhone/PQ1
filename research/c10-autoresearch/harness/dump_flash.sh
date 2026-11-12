#!/usr/bin/env bash
# Read-only evidence capture: halts at reset vector, reads FLASH_OPTR, UID, full 2 MiB flash (secure alias), then reset run.
# Usage: dump_flash.sh <out.bin>
set -u
OUT="$1"
exec openocd -f interface/stlink-dap.cfg -f target/stm32u5x.cfg \
  -c "gdb_port disabled" -c "tcl_port disabled" -c "telnet_port disabled" \
  -c init -c "reset halt" \
  -c "echo OPTR:" -c "mdw 0x40022040" \
  -c "echo UID:" -c "mdw 0x0BFA0700 3" \
  -c "reg pc" -c "reg xpsr" \
  -c "dump_image $OUT 0x0C000000 0x200000" \
  -c "reset run" -c shutdown
