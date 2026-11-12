#!/usr/bin/env bash
# stop.sh — encerra o laboratorio: QEMU, viewer web (6080) e servidor de arquivos (8000).
#
# Nao apaga nada em disco. Para liberar espaco de verdade:
#   rm -rf images/          # ISO (5.1G) + disco da VM (11G)
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
killed=0

# QEMU: o nome do processo tem mais de 15 chars, entao pgrep -x nao serve
for p in $(ps -eo pid=,comm= | awk '$2 ~ /^qemu-system/ {print $1}'); do
    if kill "$p" 2>/dev/null; then
        echo "  qemu pid=$p encerrado"
        killed=1
    fi
done

# portas auxiliares (websockify / server.py)
for port in 6080 8000; do
    pid=$(ss -ltnp 2>/dev/null | sed -n "s/.*:$port .*pid=\([0-9]*\).*/\1/p" | head -1)
    if [ -n "${pid:-}" ]; then
        if kill "$pid" 2>/dev/null; then
            echo "  porta $port liberada (pid=$pid)"
            killed=1
        fi
    fi
done

rm -f "$DIR/mon.sock"

if [ "$killed" = 0 ]; then
    echo "  nada estava rodando"
fi
echo "lab encerrado"
