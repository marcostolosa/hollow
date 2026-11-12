#!/usr/bin/env bash
# run.sh — sobe o Windows 11 24H2 (Enterprise Eval) para o laboratorio.
#
# Firmware: SeaBIOS (legacy). Motivo: o edk2-ovmf 202608 (Arch) nao consegue
# iniciar o CD-ROM desta ISO — "BdsDxe: failed to start Boot0002 Time out" — e
# existe regressao conhecida nesse build (Fedora #2537116). SeaBIOS boota a
# mesma ISO normalmente. Para o teste de injecao, o que importa e' o kernel
# 26100 (24H2); o loader e' identico em BIOS e UEFI.
#
# Sem root: QEMU em ~/.local/opt/qemu, KVM via /dev/kvm.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
Q="${QEMU_PREFIX:-$HOME/.local/opt/qemu}"
export LD_LIBRARY_PATH="$Q/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
BIN="$Q/usr/bin/qemu-system-x86_64"

ISO="${ISO:-$DIR/images/win11_24h2_eval.iso}"
DISK="$DIR/images/win11.raw"
MEM="${MEM:-2560}"
CPUS="${CPUS:-4}"

[ -x "$BIN" ] || { echo "[!] qemu nao encontrado em $BIN"; exit 1; }
[ -f "$ISO" ] || { echo "[!] ISO ausente: $ISO"; exit 1; }

[ -f "$DISK" ] || { truncate -s 64G "$DISK"; echo "[*] disco criado: 64G sparse"; }

exec "$BIN" \
  -machine pc,accel=kvm \
  -cpu host -smp "$CPUS" -m "$MEM" \
  -drive file="$DISK",format=raw,if=ide,index=0,cache=writeback \
  -drive file="$ISO",media=cdrom,readonly=on,if=ide,index=2 \
  -device qemu-xhci,id=xhci \
  -device usb-tablet,bus=xhci.0 \
  -drive "file=fat:rw:$DIR/usb",format=raw,if=none,id=usb0 \
  -device usb-storage,drive=usb0,bus=xhci.0 \
  -vga std -display none -vnc 127.0.0.1:1 \
  -monitor "unix:$DIR/mon.sock",server,nowait \
  -nic user,model=e1000 \
  -boot once=d,menu=off \
  -rtc base=localtime \
  -name hollowlab
