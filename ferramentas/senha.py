"""Avalia a força de uma senha (entropia + regras) e, opcionalmente, checa se ela já vazou
usando a API Pwned Passwords com k-anonimato (só os 5 primeiros caracteres do hash SHA-1 saem da máquina).

Uso:
    python -m ferramentas.senha            # pede a senha sem mostrar na tela
    python -m ferramentas.senha --vazamento
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import math
import re
import string

COMUNS = {"123456", "senha", "senha123", "password", "qwerty", "admin", "12345678", "brasil", "abc123", "111111"}


def entropia_bits(senha: str) -> float:
    pool = 0
    pool += 26 if re.search(r"[a-z]", senha) else 0
    pool += 26 if re.search(r"[A-Z]", senha) else 0
    pool += 10 if re.search(r"\d", senha) else 0
    pool += len(string.punctuation) if re.search(r"[^\w\s]", senha) else 0
    pool += 1 if " " in senha else 0
    return len(senha) * math.log2(pool) if pool else 0.0


def avaliar(senha: str) -> dict:
    problemas = []
    if senha.lower() in COMUNS:
        problemas.append("está entre as senhas mais comuns")
    if len(senha) < 12:
        problemas.append("tem menos de 12 caracteres")
    if re.search(r"(.)\1{2,}", senha):
        problemas.append("repete o mesmo caractere 3+ vezes")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwer)", senha.lower()):
        problemas.append("contém sequência previsível")
    bits = entropia_bits(senha)
    if senha.lower() in COMUNS:
        nivel = "Muito fraca"
    elif bits < 40:
        nivel = "Fraca"
    elif bits < 60:
        nivel = "Média"
    elif bits < 80:
        nivel = "Forte"
    else:
        nivel = "Muito forte"
    if problemas and nivel in ("Forte", "Muito forte"):
        nivel = "Média"
    return {"entropia_bits": round(bits, 1), "nivel": nivel, "problemas": problemas}


def prefixo_sufixo_sha1(senha: str) -> tuple[str, str]:
    h = hashlib.sha1(senha.encode("utf-8")).hexdigest().upper()
    return h[:5], h[5:]


def vezes_vazada(senha: str) -> int:
    import requests

    prefixo, sufixo = prefixo_sufixo_sha1(senha)
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefixo}", timeout=15,
                        headers={"Add-Padding": "true"})
    resp.raise_for_status()
    for linha in resp.text.splitlines():
        suf, qtd = linha.split(":")
        if suf == sufixo:
            return int(qtd)
    return 0


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--vazamento", action="store_true", help="consulta a base Pwned Passwords (k-anonimato)")
    a = p.parse_args()
    senha = getpass.getpass("Senha (não aparece na tela): ")
    r = avaliar(senha)
    print(f"Nível: {r['nivel']} · entropia ≈ {r['entropia_bits']} bits")
    for prob in r["problemas"]:
        print(" -", prob)
    if a.vazamento:
        n = vezes_vazada(senha)
        print(f"⚠️ Apareceu {n:,} vezes em vazamentos. Não use!" if n else "✅ Não encontrada em vazamentos conhecidos.")


if __name__ == "__main__":
    main()
