"""Monitor simples de integridade de arquivos (estilo FIM/Tripwire): cria uma linha de base com
hashes SHA-256 e depois aponta arquivos criados, alterados ou removidos.

Uso:
    python -m ferramentas.integridade baseline ./pasta   # salva .baseline.json
    python -m ferramentas.integridade verificar ./pasta
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ARQ_BASE = ".baseline.json"


def sha256(caminho: Path, bloco: int = 65536) -> str:
    h = hashlib.sha256()
    with caminho.open("rb") as f:
        while chunk := f.read(bloco):
            h.update(chunk)
    return h.hexdigest()


def mapear(pasta: Path) -> dict[str, str]:
    return {str(p.relative_to(pasta)): sha256(p) for p in sorted(pasta.rglob("*"))
            if p.is_file() and p.name != ARQ_BASE}


def comparar(base: dict[str, str], atual: dict[str, str]) -> dict[str, list[str]]:
    return {
        "criados": sorted(set(atual) - set(base)),
        "removidos": sorted(set(base) - set(atual)),
        "alterados": sorted(k for k in set(base) & set(atual) if base[k] != atual[k]),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("acao", choices=["baseline", "verificar"])
    p.add_argument("pasta", type=Path)
    a = p.parse_args()
    arq = a.pasta / ARQ_BASE
    if a.acao == "baseline":
        arq.write_text(json.dumps(mapear(a.pasta), indent=2))
        print(f"Linha de base salva em {arq}")
        return
    dif = comparar(json.loads(arq.read_text()), mapear(a.pasta))
    if not any(dif.values()):
        print("✅ Nenhuma alteração desde a linha de base.")
    for tipo, itens in dif.items():
        for i in itens:
            print(f"[{tipo.upper()}] {i}")


if __name__ == "__main__":
    main()
