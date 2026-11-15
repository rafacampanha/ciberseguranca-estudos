from pathlib import Path

from ferramentas.analisar_logs import analisar
from ferramentas.integridade import comparar, mapear
from ferramentas.phishing import classificar
from ferramentas.senha import avaliar, prefixo_sufixo_sha1

LOG = Path(__file__).resolve().parents[1] / "amostras" / "auth.log"


def test_senha_comum_e_fraca():
    assert avaliar("senha123")["nivel"] == "Muito fraca"


def test_senha_longa_e_forte():
    assert avaliar("Cafe-com-Pao-de-Queijo-2026!")["nivel"] in ("Forte", "Muito forte")


def test_k_anonimato_envia_so_5_caracteres():
    prefixo, sufixo = prefixo_sufixo_sha1("password")
    assert prefixo == "5BAA6" and len(sufixo) == 35


def test_log_detecta_forca_bruta_e_sucesso_suspeito():
    suspeitos = analisar(LOG.read_text().splitlines(), limite=5, janela_min=10)
    ips = {s.ip: s for s in suspeitos}
    assert set(ips) == {"203.0.113.45", "198.51.100.7"}      # usuária que errou 1 vez não entra
    assert ips["198.51.100.7"].logou_depois
    assert suspeitos[0].ip == "198.51.100.7"                  # crítico vem primeiro
    assert ips["203.0.113.45"].risco == "ALTO"                # tentou vários usuários


def test_integridade(tmp_path):
    (tmp_path / "a.txt").write_text("1"); (tmp_path / "b.txt").write_text("2")
    base = mapear(tmp_path)
    (tmp_path / "a.txt").write_text("alterado"); (tmp_path / "b.txt").unlink(); (tmp_path / "c.txt").write_text("3")
    assert comparar(base, mapear(tmp_path)) == {"criados": ["c.txt"], "removidos": ["b.txt"], "alterados": ["a.txt"]}


def test_phishing():
    assert classificar("http://banco-seguro-login.xyz/atualizar-conta")[1] == "ALTO"
    assert classificar("https://www.gov.br/")[1] == "BAIXO"
    assert classificar("http://192.168.0.10/login")[1] in ("MÉDIO", "ALTO")
