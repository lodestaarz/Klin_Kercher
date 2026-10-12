#!/usr/bin/env python3
"""
Atualiza a base de ameaças embutida no Klin Kercher.

Rode NO COMPUTADOR, antes de compilar o APK:

    python3 tools/atualizar_base.py

O script baixa listas públicas e grava em app/src/main/assets/base/. O app lê esses
arquivos na primeira abertura (ou quando a versão muda) e guarda tudo no banco local.
O celular nunca acessa a internet: as listas viajam dentro do APK.

Fontes:
  - MalwareBazaar (abuse.ch): hashes de arquivos maliciosos recentes (CSV, com nome da família)
  - URLhaus (abuse.ch): links que distribuem malware, ainda no ar
  - OpenPhish (feed comunitário): links de phishing

Opções:
  --chave CHAVE      chave gratuita do abuse.ch (https://auth.abuse.ch/), caso a fonte peça.
                     Também pode ser passada pela variável de ambiente ABUSECH_AUTH_KEY.
  --de-pasta PASTA   não baixa nada: usa arquivos que você baixou pelo navegador.
                     Nomes esperados na pasta: malwarebazaar.csv, urlhaus.txt, openphish.txt
  --limite N         máximo de itens por fonte (padrão 200000) para o APK não ficar grande demais
  --limpar           apaga as listas baixadas e volta para a base mínima de exemplo

Só usa a biblioteca padrão do Python (3.8 ou mais novo).
Antes de distribuir o app, confira os termos de uso de cada fonte — principalmente para uso comercial.
"""

import argparse
import datetime as dt
import io
import os
import re
import sys
import urllib.error
import urllib.request
import zipfile

RAIZ = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PASTA_BASE = os.path.join(RAIZ, "app", "src", "main", "assets", "base")

FONTES = [
    {
        "arquivo": "hashes_malwarebazaar.txt",
        "nome": "MalwareBazaar (abuse.ch)",
        "url": "https://bazaar.abuse.ch/export/csv/recent/",
        "local": "malwarebazaar.csv",
        "tipo": "hashes",
        "abusech": True,
    },
    {
        "arquivo": "urls_urlhaus.txt",
        "nome": "URLhaus (abuse.ch)",
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "local": "urlhaus.txt",
        "tipo": "urls",
        "abusech": True,
    },
    {
        "arquivo": "urls_openphish.txt",
        "nome": "OpenPhish (feed comunitário)",
        "url": "https://openphish.com/feed.txt",
        "local": "openphish.txt",
        "tipo": "urls",
        "abusech": False,
    },
]

PADRAO = {
    "hashes_padrao.txt": "Klin Kercher (exemplos de teste)",
    "dominios_padrao.txt": "Klin Kercher (exemplos de teste)",
}

HEX = re.compile(r"(?i)(?<![0-9a-f])([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])")


def baixar(url, chave=None, tentativas=2):
    cabecalhos = {"User-Agent": "KlinKercher-atualizar_base/1.0 (+app Android offline)"}
    if chave:
        cabecalhos["Auth-Key"] = chave
    erro = None
    for _ in range(tentativas):
        try:
            req = urllib.request.Request(url, headers=cabecalhos)
            with urllib.request.urlopen(req, timeout=90) as r:
                dados = r.read()
            return descompactar(dados)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise RuntimeError(
                    f"acesso negado (HTTP {e.code}). Essa fonte pode exigir a chave gratuita do abuse.ch: "
                    "crie em https://auth.abuse.ch/ e rode de novo com --chave SUA_CHAVE"
                )
            erro = e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            erro = e
    raise RuntimeError(f"falha ao baixar: {erro}")


def descompactar(dados):
    """Algumas exportações vêm em .zip; devolve o texto do primeiro arquivo."""
    if dados[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(dados)) as z:
            nomes = [n for n in z.namelist() if not n.endswith("/")]
            if not nomes:
                return ""
            dados = z.read(nomes[0])
    return dados.decode("utf-8", errors="replace")


def ler_local(pasta, nome):
    caminho = os.path.join(pasta, nome)
    if not os.path.exists(caminho):
        raise RuntimeError(f"arquivo não encontrado: {caminho}")
    with open(caminho, "rb") as f:
        return descompactar(f.read())


def filtrar(texto, tipo, limite):
    """Mantém comentários de cabeçalho e até `limite` linhas válidas."""
    saida, validas = [], 0
    for linha in texto.splitlines():
        l = linha.strip()
        if not l:
            continue
        if l.startswith("#"):
            # preserva só o cabeçalho de colunas (o app usa para achar o nome da família)
            if "," in l and ("sha256" in l.lower() or "url" in l.lower()):
                saida.append(l)
            continue
        if tipo == "hashes" and not HEX.search(l):
            continue
        if tipo == "urls" and not re.match(r"(?i)^(https?|hxxps?)://", l.split(",")[0].strip('"')):
            continue
        saida.append(l)
        validas += 1
        if validas >= limite:
            break
    return saida, validas


def gravar_lista(fonte, linhas, validas, agora):
    caminho = os.path.join(PASTA_BASE, fonte["arquivo"])
    with open(caminho, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# {fonte['nome']}\n")
        f.write(f"# Origem: {fonte['url']}\n")
        f.write(f"# Baixado em: {agora:%d/%m/%Y %H:%M} — {validas} itens\n")
        for l in linhas:
            f.write(l + "\n")
    return caminho


def gravar_propriedades(fontes_ok, agora):
    caminho = os.path.join(PASTA_BASE, "base.properties")
    arquivos = sorted(f for f in os.listdir(PASTA_BASE) if f.endswith((".txt", ".csv")))
    nomes = dict(PADRAO)
    for f in FONTES:
        nomes[f["arquivo"]] = f["nome"]
    with open(caminho, "w", encoding="utf-8", newline="\n") as f:
        f.write("# Gerado por tools/atualizar_base.py — não edite à mão.\n")
        f.write("# Quando \"versao\" muda, o app recarrega as listas embutidas na próxima abertura.\n")
        f.write(f"versao={agora:%Y%m%d-%H%M%S}\n")
        if fontes_ok:
            f.write(f"gerado_em=atualizada em {agora:%d/%m/%Y}\n")
        else:
            f.write("gerado_em=Base mínima de exemplo (sem listas reais)\n")
        for a in arquivos:
            f.write(f"fonte.{a}={nomes.get(a, a)}\n")


def limpar(agora):
    for f in FONTES:
        caminho = os.path.join(PASTA_BASE, f["arquivo"])
        if os.path.exists(caminho):
            os.remove(caminho)
            print(f"  removido {f['arquivo']}")
    gravar_propriedades([], agora)
    print("Base voltou para os exemplos mínimos. Compile o app de novo.")


def main():
    p = argparse.ArgumentParser(description="Atualiza as listas de ameaças embutidas no Klin Kercher.")
    p.add_argument("--chave", default=os.environ.get("ABUSECH_AUTH_KEY"), help="chave gratuita do abuse.ch")
    p.add_argument("--de-pasta", dest="pasta", help="usar arquivos já baixados nesta pasta")
    p.add_argument("--limite", type=int, default=200_000, help="máximo de itens por fonte")
    p.add_argument("--limpar", action="store_true", help="remover listas baixadas")
    args = p.parse_args()

    if not os.path.isdir(PASTA_BASE):
        print(f"Pasta não encontrada: {PASTA_BASE}\nRode o script de dentro do projeto Klin_Kercher.", file=sys.stderr)
        return 2

    agora = dt.datetime.now()
    if args.limpar:
        limpar(agora)
        return 0

    ok, falhas = [], []
    for fonte in FONTES:
        print(f"→ {fonte['nome']}")
        try:
            if args.pasta:
                texto = ler_local(args.pasta, fonte["local"])
            else:
                texto = baixar(fonte["url"], args.chave if fonte["abusech"] else None)
            linhas, validas = filtrar(texto, fonte["tipo"], args.limite)
            if validas == 0:
                raise RuntimeError("a lista veio vazia ou num formato inesperado")
            gravar_lista(fonte, linhas, validas, agora)
            ok.append(fonte)
            print(f"  ok: {validas} itens → assets/base/{fonte['arquivo']}")
        except Exception as e:  # noqa: BLE001 — queremos seguir para a próxima fonte
            falhas.append(fonte)
            existente = os.path.exists(os.path.join(PASTA_BASE, fonte["arquivo"]))
            print(f"  ERRO: {e}")
            print("  (mantida a versão anterior desta lista)" if existente else "  (esta fonte ficará de fora)")

    gravar_propriedades(ok, agora)
    tamanho = sum(os.path.getsize(os.path.join(PASTA_BASE, f)) for f in os.listdir(PASTA_BASE))
    print(f"\nPronto: {len(ok)} de {len(FONTES)} fontes atualizadas. Tamanho da pasta base: {tamanho / 1024 / 1024:.1f} MB.")
    print("Agora compile o app no Android Studio. Na primeira abertura ele carrega a nova base.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
