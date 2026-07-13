# pqcheck

[![CI](https://github.com/Rafael-Ryu/pqcheck/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/Rafael-Ryu/pqcheck/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pqcheck)](https://pypi.org/project/pqcheck/)
[![Python](https://img.shields.io/pypi/pyversions/pqcheck)](https://pypi.org/project/pqcheck/)
[![License](https://img.shields.io/pypi/l/pqcheck)](LICENSE)
[![Sigstore](https://img.shields.io/badge/releases-signed%20with%20Sigstore-blue)](SECURITY.md)

Gere um Cryptography Bill of Materials (CBOM) do seu código em segundos
e bloqueie o CI com uma política de criptografia que dá para ler.

O `pqcheck` escaneia código-fonte e lockfiles de dependências em busca de
uso de algoritmos criptográficos — RSA, ECDSA, modos de AES, hashes
legados, primitivas pós-quânticas — e emite CBOM CycloneDX 1.6 + SARIF
2.1.0, avaliados contra uma política YAML versionável. Roda no laptop e
no CI, sem servidor, sem conta e sem rede durante o scan.

Por que agora: o NIST IR 8547 deprecia RSA e ECC em 2030 e os proíbe em
2035, e todo framework de migração trata o inventário como o primeiro
passo. **Nenhuma regulação brasileira exige inventário criptográfico ou
migração PQC hoje** — os perfis BR inclusos (`br-bcb-conservative`,
`br-drex-piloto`, `br-vendor-dd`) antecipam essa direção alinhados aos
controles da Res. CMN 4.893/2021, sem alegar obrigação que não existe.

**Status: pre-release.** A v0.1.0 chega ao PyPI com wheels assinadas via
Sigstore.

## Início rápido

```console
$ pqcheck scan ./seu-repo --policy br-bcb-conservative
✗ src/auth.py:42 — RSA [banned/critical, confidence high] — Shor-vulnerable
✓ src/aead.py:12 — AES [approved/info, confidence high]
policy br-bcb-conservative-0.1.0: 1 fail, 0 warn, 1 allow
```

CBOM e SARIF: `--format cbom -o cbom.cdx.json` / `--format sarif -o
pqcheck.sarif` (importa direto no GitHub Code Scanning). Gate de CI:
`--fail-on policy` (exit 1 ao reprovar) ou `pqcheck self-audit`.

Verifique um release você mesmo (extra `sigstore`; o bundle
`.sigstore.json` acompanha cada wheel no release do GitHub):
`pqcheck verify-release pqcheck-0.1.0-py3-none-any.whl`.

Cobertura: Python (hashlib, cryptography, pycryptodome) e Go (stdlib +
x/crypto, união de análise semântica via `go/types` com um passe
tree-sitter que cobre arquivos condicionados a GOOS/cgo); 6 formatos de
lockfile. Java vem a seguir no roadmap.

Precisão medida: 255 findings HIGH/CRITICAL em 10 repos públicos, todos
adjudicados manualmente — 0 falsos positivos. Recall de 1.00 sobre 527
call sites adjudicados nos mesmos repos (conjunto de tuning) e de 0.989
em 6 repos held-out nunca vistos (protocolo e caveats em
`tests/corpus/`).

## Limitações conhecidas

O `pqcheck` é um scanner estático de repositório único, e essas lacunas
vêm dessa escolha de design:

- Sem análise de dataflow: um algoritmo alcançado via variável,
  parâmetro ou lookup table passa despercebido ou vira um finding
  genérico de baixa confiança — ex.: `.digest()` chamado sobre um
  objeto de hash recebido como parâmetro, ou uma cifra escolhida de um
  dict em tempo de execução. authlib é o exemplo mais claro no corpus
  held-out.
- Sem visibilidade de extensão C/FFI: cripto implementada atrás de um
  binding Cython ou C no próprio repo — o binding OpenSSL do
  borgbackup, por exemplo — é invisível para detecção em nível de
  código-fonte; só a superfície de chamada Python ou Go é escaneada.
- Detecção limitada ao catálogo: o `pqcheck` sinaliza o que está nos
  catálogos curados de Python e Go. Uma biblioteca ou símbolo fora do
  catálogo não gera finding nenhum, e ausência de finding não é
  evidência de ausência de cripto.
- Só análise estática: não há resolução de dispatch em runtime.
  `hashlib.new(name_var)` com nome calculado em runtime, ou dispatch
  via `getattr`, não resolvem a nada.
- Cegueira de contexto de uso: um match de símbolo não carrega
  intenção. "RSA validando um webhook de terceiro" lê igual a "RSA
  criptografando dados em repouso", e uma chamada `ECDH()` usada só
  para conversão de formato de chave é sinalizada igual a um key
  agreement real (um falso positivo conhecido no conjunto held-out).
  Regras de política com escopo de contexto já são parseadas, mas não
  entram nas políticas inclusas até os detectores emitirem contexto.
- Detecção de esquema híbrido cobre só `filippo.io/hpke`
  (X25519MLKEM768); outras construções híbridas são lidas pelo
  componente clássico.
- Só o `.gitignore`/`.pqcheckignore` da raiz do repo é respeitado.
- Findings de dependência são inventário (metadado `introduces` no
  CBOM); eles não derrubam o gate de política na v0.1 — call sites
  derrubam.

Veja `tests/corpus/` para o protocolo de adjudicação por trás desses
números.

Processo de segurança e demais detalhes completos no
[README em inglês](README.md) e em [SECURITY.md](SECURITY.md).

Licença Apache-2.0.
