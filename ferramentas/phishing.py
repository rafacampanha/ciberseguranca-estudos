"""Pontua sinais de phishing em um link (heurísticas usadas em treinamentos de conscientização).

Uso:
    python -m ferramentas.phishing "http://banco-seguro-login.xyz/atualizar?conta=1"
"""
from __future__ import annotations

import ipaddress
import re
import sys
from urllib.parse import urlparse

TLDS_SUSPEITOS = {"xyz", "top", "click", "zip", "mov", "work", "rest", "cam"}
PALAVRAS_ISCA = ["login", "senha", "atualiz", "verific", "confirm", "bloque", "premio", "pix", "seguranca", "conta"]
ENCURTADORES = {"bit.ly", "tinyurl.com", "cutt.ly", "t.co", "is.gd", "encurtador.com.br"}


def sinais(url: str) -> list[tuple[str, int]]:
    u = urlparse(url if "://" in url else "http://" + url)
    host = (u.hostname or "").lower()
    achados = []
    if u.scheme != "https":
        achados.append(("não usa HTTPS", 1))
    try:
        ipaddress.ip_address(host)
        achados.append(("usa endereço IP no lugar de domínio", 3))
    except ValueError:
        pass
    if "@" in u.netloc:
        achados.append(("tem '@' no endereço (esconde o destino real)", 3))
    if host.startswith("xn--") or ".xn--" in host:
        achados.append(("domínio com caracteres internacionais (possível homógrafo)", 3))
    if host.rsplit(".", 1)[-1] in TLDS_SUSPEITOS:
        achados.append((f"extensão de domínio .{host.rsplit('.', 1)[-1]} muito usada em golpes", 2))
    if host in ENCURTADORES:
        achados.append(("link encurtado (destino escondido)", 2))
    if host.count("-") >= 2 or host.count(".") >= 4:
        achados.append(("domínio com muitos hífens/subdomínios", 2))
    iscas = [p for p in PALAVRAS_ISCA if p in url.lower()]
    if iscas:
        achados.append((f"palavras de isca: {', '.join(iscas)}", min(len(iscas), 3)))
    if re.search(r"\d{5,}", host):
        achados.append(("sequência longa de números no domínio", 1))
    return achados


def classificar(url: str) -> tuple[int, str, list[tuple[str, int]]]:
    s = sinais(url)
    pontos = sum(p for _, p in s)
    nivel = "ALTO" if pontos >= 6 else "MÉDIO" if pontos >= 3 else "BAIXO"
    return pontos, nivel, s


if __name__ == "__main__":
    for link in sys.argv[1:]:
        pts, nivel, s = classificar(link)
        print(f"\n{link}\nRisco {nivel} ({pts} pontos)")
        for txt, p in s:
            print(f"  +{p} {txt}")
