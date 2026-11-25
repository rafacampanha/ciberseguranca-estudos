# 🛡️ Estudos de Cibersegurança

[![Testes](https://github.com/rafacampanha/ciberseguranca-estudos/actions/workflows/testes.yml/badge.svg)](https://github.com/rafacampanha/ciberseguranca-estudos/actions/workflows/testes.yml)

Repositório onde registro minha jornada rumo à **cibersegurança**, com foco em **segurança defensiva (Blue Team)**: pequenas ferramentas em Python, laboratórios e anotações de estudo.

> Tudo aqui é para fins educacionais e defensivos. Os logs de exemplo usam IPs reservados para documentação (RFC 5737).

## Ferramentas

| Ferramenta | O que faz | Conceitos |
|---|---|---|
| [`senha.py`](ferramentas/senha.py) | Mede a força de uma senha e checa se ela já vazou | entropia, **k-anonimato** (só 5 caracteres do hash SHA-1 saem da máquina) |
| [`analisar_logs.py`](ferramentas/analisar_logs.py) | Detecta **força bruta SSH** em `auth.log` e marca IPs que conseguiram logar depois das falhas | regex, janela deslizante, triagem de alertas |
| [`integridade.py`](ferramentas/integridade.py) | Monitor de integridade de arquivos: aponta criados, alterados e removidos | hashing SHA-256, FIM (estilo Tripwire) |
| [`phishing.py`](ferramentas/phishing.py) | Pontua sinais de phishing em links | engenharia social, homógrafos, TLDs suspeitos |

### Exemplo: detecção de força bruta

```text
$ python -m ferramentas.analisar_logs amostras/auth.log
IP               falhas  pico  usuários tentados              risco
198.51.100.7          5     5  deploy                         CRÍTICO (sucesso após várias falhas)
203.0.113.45          6     6  admin, oracle, root, test, u   ALTO
```

### Exemplo: link suspeito

```text
$ python -m ferramentas.phishing "http://banco-seguro-login.xyz/atualizar-conta"
Risco ALTO (8 pontos)
  +1 não usa HTTPS
  +2 extensão de domínio .xyz muito usada em golpes
  +2 domínio com muitos hífens/subdomínios
  +3 palavras de isca: login, atualiz, conta
```

## Como rodar

```bash
pip install -r requirements.txt
python -m ferramentas.senha --vazamento
python -m ferramentas.analisar_logs amostras/auth.log --limite 5 --janela 10
python -m ferramentas.integridade baseline ./minha_pasta && python -m ferramentas.integridade verificar ./minha_pasta
python -m ferramentas.phishing "https://exemplo.com"
pytest
```

## Conscientização

Também desenvolvi um **treinamento de segurança da informação** para colaboradores (slides, vídeos e quiz com nota mínima de 70%) cobrindo phishing, senhas, engenharia social e uso seguro de e-mail. As heurísticas do `phishing.py` vieram desse material.

## Roadmap

Veja [`notas/roadmap.md`](notas/roadmap.md).
