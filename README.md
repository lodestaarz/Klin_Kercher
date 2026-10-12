# Klin Kercher

Detetive de links e arquivos para Android. **Funciona 100% offline**: o app não tem permissão
de internet, e nada do que você verifica sai do aparelho.

## Situação atual

| Parte | Estado |
|---|---|
| Análise de links (`core/url/`) | Pronta, com testes |
| Análise de arquivos (`core/file/`) | Pronta, com testes |
| Importação de listas (`core/importer/`) | Pronta, com testes |
| Base local SQLite (`data/`) | Pronta. Verificada pelo compilador; ainda não rodou num aparelho |
| Telas em Compose: Links, Arquivos e Base local (`ui/`) | Prontas. Verificadas pelo compilador; ainda não rodaram num aparelho |
| "Compartilhar com Klin Kercher", "Abrir com" e menu "Verificar link" | Prontos (manifesto + `MainActivity`) |
| Permissão INTERNET removida explicitamente | Pronto (`AndroidManifest.xml`) |
| Ícone do app com o logo do detetive | Pronto (ícone adaptativo + monocromático) |
| Script para baixar listas reais (`tools/atualizar_base.py`) | Pronto. Testado com arquivos locais; os downloads reais não foram testados |

**O que foi verificado:** o código de análise (Kotlin puro) passou nos **45 testes automáticos**
com o Kotlin 2.2.10, o mesmo do projeto. O app inteiro (telas Compose, ViewModel, SQLite e
`MainActivity`) passou pela verificação de tipos do compilador Kotlin + Compose, usando a API do
Android e as mesmas bibliotecas que o seu projeto já baixou. **Ainda não foi feito:** gerar o APK
pelo Gradle e rodar num celular. Esse é o primeiro passo no Android Studio.

## Como rodar

1. Abra a pasta `Klin_Kercher` no Android Studio e aguarde o *Gradle Sync*.
2. *(Opcional, mas recomendado)* Baixe listas reais de ameaças. Veja **Atualizar a base** abaixo.
3. Rode o app (▶) num celular ou emulador com Android 8.0 ou mais novo.

### Testes automáticos

No Android Studio, clique com o botão direito em `app/src/test` → **Run Tests**.
Ou, no terminal: `./gradlew test` (no Windows, `gradlew test`).

### Endereços para testar no app

| Cole na aba Links | Resultado esperado |
|---|---|
| `https://login.golpe-exemplo.test/entrar` | Perigoso: está na lista local (domínio fictício) |
| `https://nubnak.com.br` | Perigoso: nome parecido com Nubank |
| `https://g00gle.com` | Perigoso: números no lugar de letras |
| `https://nubank-seguranca.xyz/atualizar` | Perigoso: usa a marca sem ser o site oficial |
| `https://mercadolivre.com.br.ofertas.shop` | Perigoso: endereço oficial usado como disfarce |
| `https://www.bb.com.br@golpe.example.com` | Perigoso: truque do @ |
| `http://3232235777/` | Perigoso: IP disfarçado |
| `https://www.google.com/url?q=https://nubank-seguranca.xyz` | Perigoso: analisa o destino do redirecionamento |
| `https://bit.ly/abc` | Suspeito: encurtador esconde o destino |
| `https://www.nubank.com.br` | Nenhum sinal de risco (domínio oficial) |

Para a aba Arquivos, crie um arquivo de texto com a linha de teste
[EICAR](https://www.eicar.org/download-anti-malware-testfile/). Ele é inofensivo e o app deve acusá-lo.

## O que o app detecta

**Links** (`core/url/UrlAnalyzer.kt`)
- Domínios e endereços da base local, incluindo subdomínios.
- Imitação de marcas (cerca de 60, com foco em bancos, governo e serviços brasileiros, em `BrandCatalog.kt`):
  nome da marca dentro de outro domínio, erros de digitação (nubnak), números no lugar de letras
  (g00gle, paypa1) e letras de outros alfabetos que imitam as nossas (nubаnk com "а" cirílico).
- Endereço oficial usado como começo do link (`mercadolivre.com.br.ofertas.shop`).
- Truques: @ no endereço, IP disfarçado (decimal, hexadecimal ou octal), nome codificado com %xx,
  encurtadores, download de `.apk`/`.exe`, terminações gratuitas ou muito usadas em golpes, porta
  incomum, `http` sem cadeado, `javascript:` e `data:`.
- Redirecionamentos (`google.com/url?q=`, `l.facebook.com/l.php?u=`…): o destino também é
  analisado, até 3 níveis.
- Extrai os links de uma mensagem inteira (até 5 por vez).

**Arquivos** (`core/file/`)
- SHA-256, SHA-1 e MD5 calculados numa única leitura e comparados com a base local.
- Tipo real pelo conteúdo, não pelo nome: programa disfarçado (`fatura.pdf` que é um `.exe`),
  APK com nome de imagem, página HTML com nome de PDF.
- Extensão dupla (`boleto.pdf.apk`) e caractere que inverte o nome (`fdp.exe` → `exe.pdf`).
- Macros do Office (docx/xlsx/pptx e doc/xls/ppt antigos) e macros Excel 4.0.
- JavaScript em PDF, `/Launch` e anexos embutidos.
- ZIP com programa dentro e ZIP protegido por senha.
- SVG com código e o arquivo de teste EICAR.

## Atualizar a base

A base que vem no projeto é **mínima de propósito**: só o EICAR e dois domínios fictícios `.test`.
Para embutir listas reais, rode **no computador**, de dentro da pasta do projeto:

```
python3 tools/atualizar_base.py          # macOS / Linux
py tools\atualizar_base.py               # Windows
```

Fontes baixadas: **MalwareBazaar** (hashes recentes), **URLhaus** (links de malware no ar) e
**OpenPhish** (phishing). Os arquivos vão para `app/src/main/assets/base/`. Depois, compile o
app de novo: na próxima abertura ele carrega a base nova.

- Se o abuse.ch pedir chave: crie uma gratuita em https://auth.abuse.ch/ e rode com `--chave SUA_CHAVE`.
- Se preferir baixar pelo navegador: salve os arquivos como `malwarebazaar.csv`, `urlhaus.txt` e
  `openphish.txt` numa pasta e rode com `--de-pasta CAMINHO_DA_PASTA`.
- `--limpar` volta para a base mínima.
- Confira os termos de uso de cada fonte antes de distribuir o app.

Na aba **Base local** do app também dá para importar listas `.txt`/`.csv` direto no celular.

## Estrutura

```
app/src/main/java/com/example/klin_kercher/
├── MainActivity.kt          recebe "Compartilhar", "Abrir com" e "Verificar link"
├── core/                    Kotlin puro, sem Android (testável com JUnit)
│   ├── Model.kt             gravidade, veredito, interface da base
│   ├── url/                 leitura de endereços, marcas, alfabetos, análise de links
│   ├── file/                leitura única com hashes, tipo real, análise de arquivos
│   └── importer/            leitura de listas (hashes, hosts, AdBlock, CSV, URLs)
├── data/                    SQLite (ThreatDatabase), listas embutidas (BundledBase)
└── ui/                      ViewModel, telas Compose, tema e componentes
app/src/main/assets/base/    listas embutidas (geradas pelo script)
tools/atualizar_base.py      baixa as listas públicas
```

## Limites (vale explicar no trabalho)

- **Não é um antivírus completo.** A verificação por hash só reconhece arquivos que já estão na
  base. Um vírus novo, ou um arquivo modificado em um único byte, tem outro hash.
- As heurísticas de link podem errar: um site legítimo pouco conhecido que usa o nome de uma marca
  pode aparecer como suspeito, e um golpe com nome neutro (sem marca) só é pego se estiver na base.
- Encurtadores não são abertos, porque isso exigiria internet.
- PDFs com objetos compactados podem esconder JavaScript da busca simples.

## Próximo passo possível: consulta online (opcional)

Os objetivos originais citam o **Google Safe Browsing** e o **VirusTotal**. Isso continua viável,
mas exige devolver a permissão INTERNET. A arquitetura já está preparada: basta criar outra
implementação de `ThreatLookup` (em `core/Model.kt`) que consulte a API, e usá-la depois da
análise local, só quando o usuário tocar em "Consultar online".
