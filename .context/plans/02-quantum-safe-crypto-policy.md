# CryptoCT — Política de Criptografia Quantum-Safe

> Documento canônico pós-cortes. Política vinculante para todo código sob controle CryptoCT. Aplicada via `pqcheck-policy-v1.yaml` schema-validado.

---

## 1. Princípio

Quantum-safe end-to-end onde controlamos diretamente o protocolo. Onde dependemos de provider classical-only, declaramos honestamente em SECURITY.md (5 itens transitivos top-impact) com owner + mitigação compensatória. Se nosso próprio CBOM nos flagrasse num componente não-declarado, falhamos.

---

## 2. Algoritmos aprovados (8 default)

> Cripto-agilidade é estrutural (interfaces algorithm-agnostic + policy YAML), não pré-declarada com lista exaustiva. Adicionar algoritmos quando customer demand justificar.

### 2.1 KEM
| Algoritmo | Nível | Uso |
|---|---|---|
| **ML-KEM-768** (FIPS 203) | NIST L3 | Default todos KEMs |
| ML-KEM-1024 | L5 | Long-term sensitive (audit archive 7y+) |
| **Híbrido X25519MLKEM768** | Defense-in-depth | TLS 1.3 externo (obrigatório) |

### 2.2 Assinaturas digitais
| Algoritmo | Nível | Uso |
|---|---|---|
| **ML-DSA-65** (FIPS 204) | L3 | Default JWS, K-release (Phase 4), K-image, K-service |
| ML-DSA-87 | L5 | K-audit-tenant (Phase 4 BYOK); long-term archive |
| **SLH-DSA-SHA2-128s** (FIPS 205) | L1 hash-based | Anchoring Merkle root horário (Phase 4); long-term archive seal |

### 2.3 Cifras simétricas
| Algoritmo | Modo | Uso |
|---|---|---|
| **AES-256** | GCM | Default cifração at-rest e in-transit |

Nonce policy: max 2^32 encryptions per key; AAD = tenant_id + timestamp.

### 2.4 Hashes e MACs
| Algoritmo | Uso |
|---|---|
| **SHA-256** | Mínimo aceitável |
| **SHA-384** | Default HMAC, JWS, transcripts |
| **HMAC-SHA-384** | MACs, sealed tokens, webhook signatures |

### 2.5 KDFs e password hashing
| Algoritmo | Parâmetros | Uso |
|---|---|---|
| **HKDF-SHA-256** | salt mín 16B | Derivação de chaves operacionais |
| **Argon2id** | m=131072 (128MiB), t=4, p=1 | Password hashing usuário final; rehash em login após upgrade |

### 2.6 Random
| Source | Uso |
|---|---|
| Linux: `getrandom(2)` | Único permitido |
| Windows: `BCryptGenRandom` | Único permitido |
| macOS: `SecRandomCopyBytes` ou `CCRandomGenerateBytes` | Único permitido |
| `/dev/urandom` | OK fallback unix |
| `crypto/rand` Go, `secrets` Python, `crypto.randomBytes` Node | Wrappers OK |
| **Proibido em cripto:** `math/rand`, `Math.random`, `random` Python stdlib | — |

---

## 3. Algoritmos proibidos (CI bloqueante)

| Família | Específicos | Razão |
|---|---|---|
| RSA | Qualquer key size | Shor |
| ECDSA | P-256, P-384, P-521, secp256k1 | Shor |
| EdDSA puro | Ed25519, Ed448 (sem hybrid) | Shor |
| DH clássico | Qualquer | Shor |
| ECDH puro | X25519, X448 (sem hybrid) | Shor |
| Hash legado | MD5, SHA-1, RIPEMD | Colisão prática |
| Cifras legadas | DES, 3DES, RC4, Blowfish, IDEA | Múltiplos ataques |
| AES-128 | Em código novo (`context: new-code`) | Margem fina pós-Grover |
| Padding | RSA-PKCS1v1.5, RSA-OAEP-SHA1 | RSA proibido |
| Cipher modes | ECB, CFB, OFB sem AEAD | Vazamento padrão |
| Custom crypto | Tudo | Inadmissível |

**Exceções controladas** (via ADR + revisão 6m): verificação de assinaturas de terceiros (GitHub webhooks, Stripe), bridge para crypto legado durante migração.

---

## 4. Hierarquia separada de chaves

### 4.1 Phase 1-3 (current execution)

| Chave | Algoritmo | Onde mora | Quem assina | Rotação | Uso |
|---|---|---|---|---|---|
| Release signing | Sigstore keyless | Sigstore Fulcio cert per-release | GitHub Actions OIDC | Per-release | Assina releases pqcheck |
| **K-service** (Phase 3) | ML-DSA-65 | AWS CloudHSM sa-east-1 | SPIRE automation | 6m com handoff 30d | JWS service-to-service interno |
| **K-tls-leaf** (Phase 3) | ECC P-256 + sidecar ML-DSA | SPIRE | SPIRE | 24h | TLS leaf certs |

### 4.2 Phase 4 ativação (trigger: 1º Enterprise LOI)

| Chave | Algoritmo | Onde mora | Quem assina | Rotação | Uso |
|---|---|---|---|---|---|
| **K-release** | ML-DSA-65 | YubiHSM2 offline, M-of-N quorum (configured 2-of-3 — see `docs/adr/0001-mofn-quorum-rationale.md`: latency vs collusion resistance for offline ceremony) | Cerimônia | Anual + emergência | Assina releases pqcheck (sidecar) |
| **K-image** | ML-DSA-65 | AWS CloudHSM sa-east-1 | CI automatizada (não-PR runner) | 6m | Assina imagens Docker, Helm charts |
| **K-audit-tenant-{N}** | ML-DSA-87 | Customer-controllable KMS (AWS KMS BYOK / Vault / Azure KV / on-prem HSM) | Customer | Cliente define (default 1y) | Assina Merkle root do tenant N |
| **K-tls-intermediate** | ML-DSA-65 | AWS CloudHSM | Cerimônia 4-eyes | 90d | Intermediate CA |
| **K-tls-root** | ML-DSA-65 | YubiHSM2 offline, M=3-of-5 (higher quorum: long rotation cycle + irreversible compromise blast radius — see `docs/adr/0002-tls-root-quorum-rationale.md`) | Cerimônia anual | 5y | Root CA |
| **K-backup-wrapper** | ML-KEM-768 | YubiHSM2 separada da K-release | Cerimônia | 1y | Wrap backups before S3 |

**Non-correlação requerida:** K-release nunca toca K-audit-tenant; K-image nunca toca K-release; comprometimento runtime CI revoga K-image + K-service apenas (recovery 24h); K-release intacta porque offline.

**Customer KMS BYOK** (K-audit-tenant): cliente traz sua própria chave em AWS KMS sa-east-1 OR Vault on-prem OR Azure KV. Audit log encryption torna-se zero-knowledge para CryptoCT — AWS produz ciphertext inútil sob CLOUD Act demand.

---

## 5. Aplicação por camada

### 5.1 TLS público (browser → edge)
- TLS 1.3 only
- Cipher suites: `TLS_AES_256_GCM_SHA384` (preferido), `TLS_CHACHA20_POLY1305_SHA256`
- Key exchange: **`X25519MLKEM768` exclusivo** — fallback classical X25519 DESABILITADO via OpenSSL 3.5+ config
- Cert: ECC P-256 + sidecar ML-DSA (CAs públicas ainda emitem ECC até ~2027-2028)
- HSTS preload, OCSP stapling

### 5.2 mTLS interno (serviço ↔ serviço) — Phase 3
- TLS 1.3 + X25519MLKEM768 obrigatório
- Cert leaf rotação 24h via SPIRE/SPIFFE
- Cert signing chain: ML-DSA-65 root + intermediate
- mTLS verificação bidirecional, sem fallback
- Certificate pinning em Workers → AWS PrivateLink

### 5.3 Cloudflare Workers → AWS sa-east-1
- Cloudflare Tunnel + AWS PrivateLink (Phase 3)
- mTLS hybrid PQC + certificate pinning bilateral
- Workers stateless — não armazena CBOM/customer data
- Workers logs retention 24h max; PII scrub em path params + header values

### 5.4 Banco de dados — Phase 3
- TLS hybrid PQC
- Encryption-at-rest: client-side AES-256-GCM com KEK em AWS KMS sa-east-1 para campos sensíveis (OAuth tokens, PII); customer KMS BYOK na Phase 4
- KEK rotation 90d com 30d overlap
- RLS multi-tenant via SESSION mode PgBouncer (`04-security-operations.md §3`)
- Backups: AES-256-GCM com key wrap ML-KEM-768

### 5.5 Object storage
- TLS PQC obrigatório
- Server-side encryption AES-256-GCM (Phase 1-3)
- **Phase 4:** S3 Object Lock Compliance mode com múltiplas KMS keys (scattered deletion schedule) para audit archive; KMS key deletion 30-day cooling + 4-eyes approval; CRR disabled; Glacier disabled
- CBOMs e artefatos cliente: S3 sa-east-1 (não R2)

### 5.6 Secrets management
- Phase 1-2: GitHub Secrets
- Phase 3+: AWS Secrets Manager + envelope encryption local
- DEK por secret cifrado com KEK em AWS KMS sa-east-1
- Acesso só via mTLS + STS short-lived (15min)
- Phase 4: sops PQC fork para GitOps secrets

### 5.7 Auth tokens
| Tipo | Algoritmo | Armazenamento |
|---|---|---|
| Session cookie | HMAC-SHA-384 sealed + AES-256-GCM body | `HttpOnly; Secure; SameSite=Strict` — NÃO localStorage |
| API key | Random 32-byte + Argon2id (m=128MiB t=4 p=1) + HMAC-SHA-384 lookup index com pepper rotacionado (pepper isolado em CloudHSM sign/verify operations — NÃO mora no mesmo Secrets Manager scope do `cryptoct_app` role) | RDS sa-east-1 |
| OAuth access token | ML-DSA-65 JWS (Phase 3) | RDS sa-east-1 client-side encrypted |
| OAuth refresh token | Random 64-byte + Argon2id + rotação | RDS sa-east-1 |
| Webhook signature | HMAC-SHA-384 com nonce + timestamp window 5min — persist nonces for window × 2 (10min) with monotonic-clock validation; reject re-use within retention period | — |
| GitHub App JWT | RS256 (limitação GitHub upstream) | Memory only |

### 5.8 Audit log

**Phase 3:**
- Append-only via `SECURITY DEFINER` stored procedure
- DBA UPDATE/DELETE bloqueado via PG event triggers
- Hourly Merkle tree assinado com K-service
- Sigstore Rekor single anchor
- Retenção por classe de evento auditável: (a) eventos PLD/AML → Lei 9.613/1998 Art. 10 (5 anos); (b) eventos BCB-regulados → Resolução BCB 119/2021 + Circular 4.001/2020 (sucessoras de Circ. 3.978/2020 revogada), retenção 5 anos; (c) subset cardholder-data → PCI-DSS v4.0.1 Req. 10.5.1 (12 meses mínimo conforme spec; 3y total via orientação Visa/Mastercard); (d) eventos com PII fora dessas classes → 30 dias com **LGPD Art. 16 I carve-out** documentado (cumprimento de obrigação legal/regulatória pelo controlador) para PII tombstoning. Object Lock COMPLIANCE retention configurada por lifecycle rule por classe — não um valor universal. Phase 4 BYOK + per-data-subject DEKs documentado como defence-in-depth, NÃO como substituto de Art. 18 §5.

**Phase 4 ativação:**
- + Multi-region S3 sync per-insert
- + Customer KMS BYOK sign (K-audit-tenant-{N})
- + Triple anchor 3-of-3 quorum: S3 Object Lock Compliance 7y + Sigstore Rekor + RFC 3161 TSA (DigiCert + e-Sec Brasil + 1 outro)
- + Long-term archive: SLH-DSA-SHA2-128s assinatura mensal sobre Merkle root anual
- + Verificação cliente independente via `pqcheck audit-verify --rekor-witness --tsa-witness --kms-pubkey customer.pub --quorum-required 3`

### Boundary attestation Phase 3 → Phase 4

When a tenant transitions from Phase 3 (K-service signs anchors server-side) to Phase 4
(K-audit-tenant-{N} signs anchors customer-side), the LAST Phase-3 Merkle root MUST be
co-signed by the newly-provisioned K-audit-tenant-{N} and Rekor-anchored. This creates
a verifiable chain across the phase boundary.

K-service rotation register: publish historical K-service public-key fingerprints at
`keys.cryptoct.com/k-service-rotation.json` (Phase 3 hard blocker). Phase-3 anchors
verify against this register; Phase-4 anchors verify against the customer key.
Per-tenant transition attestation stored in customer audit log + Rekor.

Without this boundary attestation, the integrity claim of "Sigstore Rekor immutable"
(04:115) does not survive phase transitions — a SOC 2 CC7.1 auditor would flag the gap.

### 5.9 Email + comunicação externa
- MTA-STS + DANE + DKIM (Ed25519 com sidecar ML-DSA quando vendor suportar)
- SPF strict
- Atos sensíveis (compliance reports, audit trails): download portal HTTPS PQC + assinatura ML-DSA-65 (Phase 3+)

---

## 6. Cerimônia signing key (K-release) — Phase 4 trigger-based

> Toda esta seção é ativada apenas no Phase 4 (trigger: 1º Enterprise LOI assinado). Phase 1-3 usam Sigstore keyless via GitHub Actions OIDC.

### 6.1 Modelo normal (cofounders + outside witness disponíveis)

Quorum: 2-of-3 Shamir Secret Sharing (rationale: per-key quorum sized to latency vs collusion-resistance trade-off; see `docs/adr/0001-mofn-quorum-rationale.md`), com mitigação de Shamir-RAM-reconstruction risk via OPSEC reforçado (see `docs/adr/0003-shamir-ram-opsec.md`).

**Material:**
- 3× YubiHSM2 (Yubico US direto OR revendedor BR oficial; firmware verified)
- 1× hardware laptop dedicado (não reused entre cerimônias)
- Tails OS USB pinned a versão específica + SHA-256 + GPG fingerprint registrados em `scripts/ceremony/README.md` AND `tails-pinning.yaml` (signed by ≥2 of {founder, outside witness}). Ceremony tool refuses unless the pin matches and is co-signed.

  **Residual risk (named explicitly):** the Tails project itself remains a single trust
  root — a coerced Tails release signed with the legitimate Tails signing key passes
  every check. The pinning defends against download-time tampering but NOT against
  upstream-key coercion. Founder responsibility: quarterly Tails-key-state review
  (Tails rotates on a multi-year cadence) — see `docs/adr/0004-ceremony-trust-root.md`.

  **Independent-fetch protocol:** witness fetches ISO via Tor mirror; operator fetches
  via clearnet; hashes compared on Signal voice channel and recorded into ceremony video.
  Mirror set fixed in `scripts/ceremony/README.md`.
- Câmera para gravação testemunhada
- Cofre físico ou caixa-forte bancária para YubiHSM2 #3 (share 3, backup)
- Sala segura sem WiFi/cellular (offline garantido por hardware switch)

**Participantes (M=2-of-3):**
- Founder técnico
- Founder operacional
- Outside witness (auditor independente OR advogada de confiança com ML-DSA-65 key bound a identidade legal via cartório)

**Steps:**
1. Tabletop dry-run com fake artifacts antes da cerimônia real
2. Outside witness verifica Tails ISO SHA-256 + GPG fingerprint out-of-band em hardware separado
3. Air-gapped boot Tails no laptop dedicated
4. Gerar K-release ML-DSA-65 keypair em SoftHSM efêmero
5. Shamir Secret Share (3 shares, threshold 2)
6. Cada share gravada em YubiHSM2 distinto, PIN diferente per holder
7. YubiHSM2 #3 (backup) selada e armazenada em cofre bancário separado
8. Public key publicada em: `pqcheck-key.pub` no repo (CODEOWNERS protected); `keys.cryptoct.com/k-release.pub`; Sigstore Rekor anchored; DNS TXT record `_pqcheck-key.cryptoct.com`. K-service rotation register publicado em paralelo em `keys.cryptoct.com/k-service-rotation.json` (historical pubkey fingerprints).
9. Hardware laptop secureerase NVMe imediatamente pós-cerimônia
10. Cerimônia gravada e arquivada (S3 Object Lock 10y)
11. Ata assinada pelos 3 participantes + notarizada (cartório SP) + ISO hash registrado

### 6.2 Uso operacional (signing release) — Broker pattern

> CI NUNCA toca K-release. Pattern: tag-push side fica em CI runner; courier side é humano com YubiHSM2.

```
Tag-push side (GitHub Actions self-hosted sa-east-1, ephemeral 1-job-per-VM):
  1. Build hermetic via cibuildwheel
  2. Sigstore sign (runner-resident; ECDSA Fulcio cert OK como classical sidecar)
  3. NÃO assinar com K-release aqui
  4. Upload artifacts para s3://cryptoct-pending-signatures/<tag>/ (lifecycle 7d expiry)
  5. SQS message para sign-queue (FIFO)
  6. Poll s3://cryptoct-signatures/<tag>/ a cada 5min, timeout 24h
  7. Quando .mldsa-sig presente: verifica Rekor entry + attach + publish PyPI + GH Release

Courier side (humano, offline):
  1. Founder técnico recebe alerta PagerDuty
  2. Verifica build via aws s3 ls
  3. Agenda slot 2h com founder operacional + outside witness
  4. Tabletop check + boot Tails (ISO hash re-verified)
  5. Rodar pqcheck-courier sign --input ./tag/ --output ./signed/
     - Pede PIN YubiHSM2-1 → atestação 1
     - Pede PIN YubiHSM2-2 → atestação 2
     - Combina via Shamir-RAM
     - Produz .mldsa-sig per artifact
     - Gera Rekor record offline
  6. Outside witness assina ata digital com chave pessoal ML-DSA-65
  7. Boot normal laptop online (ou laptop secondary)
  8. rsync .mldsa-sig para s3://cryptoct-signatures/<tag>/
  9. rekor-cli upload
  10. Boot Tails novamente, secureWipe USB courier media + secureerase NVMe
```

### 6.3 Recovery / rotation

- **Comprometimento suspeito de 1 share:** rotação imediata via cerimônia 2-of-3 com restante; share comprometida revogada via Rekor; pub key nova publicada com transitional 30d
- **Comprometimento confirmado de 2+ shares:** emergency procedure — todos artifacts re-assinados com nova K-release pós-cerimônia; warning público; CVE publicado
- **Backup recovery:** YubiHSM2 #3 ativado em cerimônia 3-of-3 com new shares

### 6.4 Degraded-mode pattern (survival branch)

Solo founder ativo (master plan §9 trigger):

**Mecanismo selecionado: Time-locked single-signer com mandatory 7-day Rekor witness delay**
- Solo founder assina com K-release Shamir share 1 sozinho + "delay attestation" record commitado em Sigstore Rekor com `not-before: T+168h` explicit timestamp
- PyPI release publicado APENAS após T+168h
- Durante 168h window, qualquer party pode challenge release via `pqcheck.com/release-challenges/<tag>`
- Após 168h sem challenges, release auto-promoting para PyPI público
- Durante window, wheel disponível APENAS via `pip install pqcheck==X.Y.Z-rc.1` pre-release tag (opt-in)

**Activation:** master-plan §9 survival trigger fires; founder team documented as solo por ≥90 days; ADR filed.

**Tooling:** `pqcheck-courier --degraded-mode` flag requer `--degraded-mode-adr <path>` argument, emite warning stdout, força `--time-lock-hours=168`, registra event em S3 audit recording.

---

## 7. Cripto-agilidade

Toda crypto é plugável:

- Algoritmo + parâmetros em `pqcheck-policy-v1.yaml` (não hardcoded)
- KEM/signature wrappers expõem interface única `KEM`/`Signer`/`Verifier`
- Migração testada via game day (semestral até Phase 3; trimestral em Phase 4)
- CBOM próprio CryptoCT publicado mensalmente (source) — infrastructure CBOM weekly = Phase 4
- Inventário de chaves com data de rotação em `keys-inventory.yaml`

---

## 8. Transitive PQC Risk (5 itens top-impact)

> Substitui a antiga tabela D1-D22 de 22 itens. Detalhe completo em SECURITY.md. Revisão anual ou quando upstream provider anuncia PQC roadmap.

| # | Item | Cripto atual | Owner | Mitigação |
|---|---|---|---|---|
| T1 | GitHub App JWT | RS256 (RSA-2048) | Eng lead | TLS PQC outer + ML-DSA-65 sig em PR comment payload (Phase 3) |
| T2 | Sigstore Fulcio cert | ECDSA P-256 | Eng lead | Phase 3: sidecar ML-DSA-65 detached; `pqcheck verify-release` recomendado ABOVE `cosign verify-blob` |
| T3 | AWS KMS HSM | RSA/ECC | Infra | BYOK customer KMS para audit log na Phase 4 (zero-knowledge); envelope encryption local com AES-256-GCM |
| T4 | Stripe TLS (US-hosted) | Classical TLS | CFO | Watch; aguardando Stripe PQC roadmap |
| T5 | Browser TLS CA pública | ECC | Infra | Hybrid X25519MLKEM768 key exchange compensa |

**Revisão anual.** Items que viram quantum-safe são removidos. Items novos descobertos via infrastructure CBOM (Phase 4) são adicionados.

---

## 9. Bibliotecas aprovadas

| Linguagem | Lib primária | Lib PQC | Notas |
|---|---|---|---|
| Python | `cryptography` ≥ 43 | **NÃO shipped em production release path** (oqs-python explicitly excluído de v0.1.x via 03 pyproject.toml); Phase 3+ broker pattern usa CIRCL-Go (Go-native, sem cgo bridge) via subprocess helper | |
| Go | stdlib `crypto/*` 1.24+ (`crypto/mlkem` nativo) | `github.com/cloudflare/circl` (Phase 3: pinned a commit SHA + vendored) | CIRCL primary |
| TypeScript/JS | Web Crypto API | `@noble/post-quantum` | Workers; sem deps nativas |
| Rust | `rustls` ≥ 0.23 + `rustls-pqc` | `pqcrypto` crate | Tooling crítico (Phase 5+) |

**Proibido:** Bouncy Castle Java sem PQC patches, OpenSSL < 3.5, qualquer fork não-mantido, `oqs-python` em qualquer release path (decisão consolidada em 03:158-165: NO `pqc-preview` extra; reintroduzir apenas via CIRCL-Go bridge quando broker-pattern verification shippar v0.3+).

### 9.1 ChaCha20-Poly1305 status

Suportado em TLS 1.3 transport cipher (`TLS_CHACHA20_POLY1305_SHA256` em §5.1) por requisito RFC 8446. **Não aprovado** para application-level encryption — política §2.3 mantém AES-256-GCM como default exclusivo para at-rest e in-transit application data. ChaCha20-Poly1305 em código de aplicação requer ADR + exception EXC-NNN.

---

## 10. Validação CI bloqueante

### 10.1 CI bloqueia merge se:

- `pqcheck scan packages/ --policy pqcheck-policy-v1.yaml --strict` detecta algoritmo proibido
- Dep nova introduz algoritmo proibido em path direto
- Cert TLS de teste falha em handshake PQC obrigatório
- Mocks de crypto usam algoritmo proibido (até em teste)
- Schema validation CycloneDX 1.6 falha

### 10.2 Audit anual (Phase 3+)

- Pen-test externo focado em downgrade attacks (PQC → classical)
- Game day: simular ML-KEM-768 quebrado, migração 4h
- Revisão lista de exceções → revogação ou renovação
- Revisão Transitive PQC Risk §8

### 10.3 Métricas

- % TLS handshakes PQC: alvo 100% interno (Phase 3+), ≥ 80% externo
- # algoritmos proibidos detectados em código próprio: alvo 0
- Tempo mediano rotação chave crítica: alvo < 7d
- Cobertura CBOM da própria stack: 100% source (Phase 1+)
- Precision do scanner em corpus público: > 0.85 HIGH/CRITICAL; alerta se < 0.90
- # FPs reportados por clientes: < 5/mês em GA

---

## 11. Disclosure e bug bounty

### 11.1 Phase 1-2 disclosure

- `SECURITY.md` no repo com:
  - GPG key
  - Signal contact founders
  - Email security@cryptoct.com
- Resposta inicial: 24h (best effort founders)
- Hall of fame público em SECURITY.md

### 11.2 Bug bounty (Phase 3 activate)

- **Intigriti** BR-friendly, ativo após gatilho Phase 3 (ARR > R$ 800k OR Series Seed signed, per 01:71) — honra a disjunção; não exigir ambos
- Scope: pqcheck CLI, GitHub App, dashboard SaaS, API endpoints
- Out of scope: social engineering, DoS attacks, automated scanner output without PoC
- Payouts: Critical USD 5k-15k, High USD 1k-5k, Medium USD 250-1k, Low USD 50-250
- SLA: triage 24h, fix critical 30d, high 90d, medium 180d
- Safe-harbor language: reviewed by legal

### 11.3 Anti-typosquat monitoring

- Socket.dev + Phylum (free tiers)

---

## 12. Auditoria desta política

Revisada:
- Após cada major release NIST (FIPS update, draft novo)
- A cada 6 meses no mínimo
- Imediatamente se qualquer algoritmo aqui é parcialmente quebrado em research público
- Annual review da Transitive PQC Risk §8

Mudanças via ADR + PR + review de 2 pessoas + signoff CTO/Security lead. Mudanças no `pqcheck-policy-v1.yaml` shipped passam por CODEOWNERS gate (founder approval obrigatória).

---

## 13. ANEXO: `pqcheck-policy-v1.yaml` template

```yaml
apiVersion: pqcheck.cryptoct.com/v1
kind: CryptoPolicy
metadata:
  name: cryptoct-default
  version: 1.0.0
  publisher: CryptoCT
  applies-to: "All new code in CryptoCT-controlled repositories"
  effective-from: "2026-05-22"
  review-date: "2026-11-22"

spec:
  default-action: warn

  approved:
    - { family: kem, algorithm: ML-KEM, parameter-sets: ["768", "1024"], action: allow }
    - { family: signature, algorithm: ML-DSA, parameter-sets: ["65", "87"], action: allow }
    - { family: signature, algorithm: SLH-DSA, parameter-sets: ["SHA2-128s"], action: allow, context: archive }
    - { family: symmetric-cipher, algorithm: AES, parameter-sets: ["256"], modes: ["GCM"], action: allow }
    - { family: hash, algorithm: SHA-256, action: allow }
    - { family: hash, algorithm: SHA-384, action: allow, preferred: true }
    - { family: mac, algorithm: HMAC, hash: ["SHA-256", "SHA-384"], action: allow }
    - { family: kdf, algorithm: HKDF, hash: ["SHA-256"], action: allow }
    - family: kdf
      algorithm: Argon2id
      params: { memory-kib-min: 131072, iterations-min: 4, parallelism-min: 1 }
      action: allow

  hybrid-required:
    - { context: tls-external, classical: ["X25519", "X448"], pqc: ["ML-KEM-768", "ML-KEM-1024"], action: allow }

  banned:
    - { family: asymmetric-encryption, algorithm: RSA, action: fail, severity: critical, reason: "Shor — migrate to ML-KEM-768" }
    - { family: signature, algorithm: ECDSA, action: fail, severity: critical, reason: "Shor — migrate to ML-DSA-65" }
    - { family: signature, algorithm: EdDSA, curves: ["Ed25519", "Ed448"], context: standalone, action: fail, severity: critical }
    - { family: key-agreement, algorithm: DH, action: fail, severity: critical }
    - { family: key-agreement, algorithm: ECDH, context: standalone, action: fail, severity: critical }
    - { family: hash, algorithm: MD5, action: fail, severity: critical, reason: "Collision-broken" }
    - { family: hash, algorithm: SHA-1, action: fail, severity: critical, reason: "Collision-broken" }
    - { family: symmetric-cipher, algorithm: DES, action: fail, severity: critical }
    - { family: symmetric-cipher, algorithm: 3DES, action: fail, severity: critical }
    - { family: symmetric-cipher, algorithm: RC4, action: fail, severity: critical }
    - family: symmetric-cipher
      algorithm: AES
      parameter-sets: ["128"]
      context: new-code
      action: fail
      severity: high
      reason: "AES-128 has only 64-bit post-Grover security margin. Use AES-256 in new code."
    - family: symmetric-cipher
      algorithm: AES
      modes: ["ECB", "CBC", "CFB", "OFB"]
      context: without-aead
      action: warn
      severity: medium

  exceptions:
    - id: EXC-001
      description: "GitHub App JWT requires RS256 per GitHub upstream limitation"
      banned-algorithm: RSA
      context: github-app-jwt
      adr: docs/adr/004-github-app-jwt.md
      review-date: "2026-09-30"
      compensating-controls:
        - "TLS PQC outer"
        - "ML-DSA-65 signature on PR comment payload (Phase 3)"
        - "Webhook nonce + timestamp window 5min for anti-replay"
    - id: EXC-002
      description: "Verify-only Stripe webhook signatures (HMAC-SHA-256 upstream)"
      banned-algorithm: null
      context: stripe-webhook-verify
      adr: docs/adr/007-stripe-webhook.md
      review-date: "2027-01-15"
      compensating-controls:
        - "Idempotency: (provider, provider_event_id) UNIQUE"
        - "Nonce + timestamp window"

  severity-rules:
    - { confidence-band: high,   action: as-declared }      # >= 0.8
    - { confidence-band: medium, action: demote-one-tier }  # 0.5-0.8
    - { confidence-band: low,    action: demote-two-tiers } # < 0.5

  fail-on:
    - severity: critical
    - { severity: high, confidence-band: ["high"] }
  warn-on:
    - severity: medium
    - { severity: high, confidence-band: ["medium", "low"] }
  info-only:
    - severity: low
    - severity: info
```

---

## 14. JSON Schema (resumido)

Schema completo em `pqcheck-policy.schema.json`. Estrutura validável:
- `apiVersion: pqcheck.cryptoct.com/v1`
- `kind: CryptoPolicy`
- `metadata.{name, version (semver), publisher, applies-to, effective-from, review-date}`
- `spec.{default-action, approved[], banned[], hybrid-required[], exceptions[], severity-rules[], fail-on[], warn-on[], info-only[]}`
- Algorithm rules: `{family, algorithm, parameter-sets[], curves[], modes[], context, action, severity, reason, migration-doc, preferred}`
- Exceptions: `{id (EXC-NNN), description, banned-algorithm, context, adr, review-date, compensating-controls[]}`

Validador: `pqcheck policy validate <file.yaml>` ou `python -m pqcheck.policy.loader <file.yaml>`.
