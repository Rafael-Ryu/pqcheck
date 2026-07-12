# pqcheck

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
`pqcheck verify-release pqcheck-0.0.1-py3-none-any.whl`.

Cobertura: Python (hashlib, cryptography, pycryptodome) e Go (stdlib +
x/crypto, com análise semântica via `go/types`); 6 formatos de lockfile.
Java vem a seguir no roadmap.

Precisão medida: 230 findings HIGH/CRITICAL em 10 repos públicos, todos
adjudicados manualmente — 0 falsos positivos (protocolo em
`tests/corpus/`). Caveat honesto: recall ainda não foi medido.

Limitações conhecidas, processo de segurança e detalhes completos no
[README em inglês](README.md) e em [SECURITY.md](SECURITY.md).

Licença Apache-2.0.
