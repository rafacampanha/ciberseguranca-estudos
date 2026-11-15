"""Detecta tentativas de força bruta em logs de autenticação SSH (formato /var/log/auth.log).

Uso:
    python -m ferramentas.analisar_logs amostras/auth.log --limite 5 --janela 10
"""
from __future__ import annotations

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

PADRAO_FALHA = re.compile(
    r"^(?P<data>\w{3}\s+\d+\s[\d:]{8}).*sshd\[\d+\]: Failed password for (invalid user )?(?P<usuario>\S+) from (?P<ip>[\d.]+)")
PADRAO_SUCESSO = re.compile(
    r"^(?P<data>\w{3}\s+\d+\s[\d:]{8}).*sshd\[\d+\]: Accepted \S+ for (?P<usuario>\S+) from (?P<ip>[\d.]+)")


@dataclass
class Suspeito:
    ip: str
    falhas: int = 0
    usuarios: set[str] = field(default_factory=set)
    pico_na_janela: int = 0
    logou_depois: bool = False

    @property
    def risco(self) -> str:
        if self.logou_depois:
            return "CRÍTICO (sucesso após várias falhas)"
        return "ALTO" if len(self.usuarios) > 3 else "MÉDIO"


def _data(txt: str, ano: int) -> datetime:
    return datetime.strptime(f"{ano} {' '.join(txt.split())}", "%Y %b %d %H:%M:%S")


def analisar(linhas, limite: int = 5, janela_min: int = 10, ano: int = 2026) -> list[Suspeito]:
    falhas: dict[str, list[datetime]] = defaultdict(list)
    usuarios: dict[str, set[str]] = defaultdict(set)
    sucessos: dict[str, list[datetime]] = defaultdict(list)
    for linha in linhas:
        if m := PADRAO_FALHA.search(linha):
            falhas[m["ip"]].append(_data(m["data"], ano)); usuarios[m["ip"]].add(m["usuario"])
        elif m := PADRAO_SUCESSO.search(linha):
            sucessos[m["ip"]].append(_data(m["data"], ano))

    janela = timedelta(minutes=janela_min)
    resultado = []
    for ip, tempos in falhas.items():
        tempos.sort()
        pico, ini = 0, 0
        for fim in range(len(tempos)):              # janela deslizante
            while tempos[fim] - tempos[ini] > janela:
                ini += 1
            pico = max(pico, fim - ini + 1)
        if pico >= limite:
            s = Suspeito(ip, len(tempos), usuarios[ip], pico)
            s.logou_depois = any(t > tempos[limite - 1] for t in sucessos.get(ip, []))
            resultado.append(s)
    return sorted(resultado, key=lambda s: (not s.logou_depois, -s.falhas))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("arquivo")
    p.add_argument("--limite", type=int, default=5, help="falhas na janela para considerar suspeito")
    p.add_argument("--janela", type=int, default=10, help="janela em minutos")
    a = p.parse_args()
    with open(a.arquivo, encoding="utf-8", errors="ignore") as f:
        suspeitos = analisar(f, a.limite, a.janela)
    print(f"{'IP':<16}{'falhas':>7}{'pico':>6}  {'usuários tentados':<30} risco")
    for s in suspeitos:
        print(f"{s.ip:<16}{s.falhas:>7}{s.pico_na_janela:>6}  {', '.join(sorted(s.usuarios))[:28]:<30} {s.risco}")
    if not suspeitos:
        print("Nenhum padrão de força bruta encontrado.")


if __name__ == "__main__":
    main()
