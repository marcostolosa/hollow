#!/usr/bin/env python3
"""vnc.py — controle de mouse/teclado no QEMU via RFB (VNC), sem cliente externo.

Uso:
  vnc.py click <x> <y> [--port 5901]
  vnc.py key <nome|0xffff> [--port 5901]
  vnc.py type <texto> [--port 5901]

Implementa so' o necessario do RFB 3.8: handshake sem autenticacao, ClientInit,
e as mensagens PointerEvent (tipo 5) e KeyEvent (tipo 4).
"""

import argparse
import socket
import sys
import time

KEYS = {
    "enter": 0xFF0D,
    "return": 0xFF0D,
    "tab": 0xFF09,
    "esc": 0xFF1B,
    "space": 0x0020,
    "backspace": 0xFF08,
    "delete": 0xFF9F,
    "up": 0xFF52,
    "down": 0xFF54,
    "left": 0xFF51,
    "right": 0xFF53,
    "home": 0xFF50,
    "end": 0xFF57,
    "f10": 0xFFC7, "shift": 0xFFE1, "ctrl": 0xFFE3, "alt": 0xFFE9,
}

# QEMU mapeia keysym->scancode sem nivel de shift; enviamos Shift explicito.
SHIFTED = {
    ":": ";", "*": "8", "?": "/", '"': "'", "<": ",", ">": ".",
    "_": "-", "+": "=", "(": "9", ")": "0", "{": "[", "}": "]",
    "|": "\\", "!": "1", "@": "2", "#": "3", "$": "4", "%": "5",
    "^": "6", "&": "7", "~": "`",
}


class Rfb:
    def __init__(self, host: str, port: int):
        self.s = socket.create_connection((host, port), timeout=10)
        self.s.settimeout(10)
        self._handshake()

    def _recv(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("conexao fechada")
            buf += chunk
        return buf

    def _handshake(self) -> None:
        self.version = self._recv(12)
        self.s.sendall(b"RFB 003.008\n")

        n = self._recv(1)[0]
        types = self._recv(n)
        if 1 not in types:
            raise SystemExit(f"servidor exige autenticacao (tipos={list(types)})")
        self.s.sendall(bytes([1]))  # None
        result = int.from_bytes(self._recv(4), "big")
        if result != 0:
            raise ConnectionError(f"segurança rejeitada: {result}")

        self.s.sendall(bytes([1]))  # shared
        self.width = int.from_bytes(self._recv(2), "big")
        self.height = int.from_bytes(self._recv(2), "big")
        self._recv(16)  # pixel format
        name_len = int.from_bytes(self._recv(4), "big")
        self.name = self._recv(name_len).decode(errors="replace")

    def pointer(self, x: int, y: int, mask: int = 0) -> None:
        self.s.sendall(bytes([5, mask]) + x.to_bytes(2, "big") + y.to_bytes(2, "big"))

    def click(self, x: int, y: int) -> None:
        self.pointer(x, y, 0)
        time.sleep(0.08)
        self.pointer(x, y, 1)
        time.sleep(0.12)
        self.pointer(x, y, 0)

    def key_down(self, keysym: int) -> None:
        self.s.sendall(bytes([4, 1, 0, 0]) + keysym.to_bytes(4, "big"))

    def key_up(self, keysym: int) -> None:
        self.s.sendall(bytes([4, 0, 0, 0]) + keysym.to_bytes(4, "big"))

    def key(self, keysym: int) -> None:
        self.key_down(keysym)
        time.sleep(0.05)
        self.key_up(keysym)

    def combo(self, keysyms: list[int]) -> None:
        for k in keysyms[:-1]:
            self.key_down(k)
            time.sleep(0.04)
        self.key(keysyms[-1])
        time.sleep(0.04)
        for k in reversed(keysyms[:-1]):
            self.key_up(k)

    def type_text(self, text: str) -> None:
        # QEMU mapeia keysym->scancode sem nivel de shift: ':','*','?' etc.
        # precisam de Shift explicito, senao saem como ';','8','/'.
        for ch in text:
            if ch in SHIFTED:
                self._shifted(ord(SHIFTED[ch]))
            else:
                self.key(ord(ch))

    def _shifted(self, keysym: int) -> None:
        self.key_down(0xFFE1)
        time.sleep(0.02)
        self.key(keysym)
        self.key_up(0xFFE1)

    def close(self) -> None:
        self.s.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["click", "key", "type", "combo", "seq", "info"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5901)
    a = ap.parse_args()

    r = Rfb(a.host, a.port)
    if a.action == "info":
        print(f"{r.width}x{r.height} name={r.name!r}")
    elif a.action == "click":
        r.click(int(a.args[0]), int(a.args[1]))
        print(f"click {a.args[0]},{a.args[1]}")
    elif a.action == "key":
        k = a.args[0].lower()
        keysym = KEYS.get(k, int(k, 0) if k.startswith("0x") else None)
        if keysym is None:
            raise SystemExit(f"tecla desconhecida: {k}")
        r.key(keysym)
        print(f"key {k}")
    elif a.action == "combo":
        seq = []
        for tok in a.args:
            t = tok.lower()
            seq.append(KEYS.get(t, int(t, 0) if t.startswith("0x") else None))
        if any(x is None for x in seq):
            raise SystemExit(f"combo invalido: {a.args}")
        r.combo(seq)
        print(f"combo {'+'.join(a.args)}")
    elif a.action == "seq":
        for step in " ".join(a.args).split("|"):
            step = step.strip()
            if not step:
                continue
            op, _, val = step.partition(":")
            if op in ("wait", "sleep"):
                time.sleep(float(val))
            elif op == "type":
                r.type_text(val)
            elif op == "key":
                k = val.lower()
                r.key(KEYS.get(k) or int(k, 16))
            elif op == "combo":
                seq = [KEYS.get(x.strip(), int(x.strip(), 16) if x.strip().startswith("0x") else None)
                       for x in val.split(",")]
                if any(x is None for x in seq):
                    raise SystemExit(f"combo invalido: {val}")
                r.combo(seq)
            else:
                raise SystemExit(f"passo desconhecido: {step}")
        print("seq ok")
    elif a.action == "type":
        r.type_text(" ".join(a.args))
        print("typed")
    r.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
