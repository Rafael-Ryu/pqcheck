# CryptoCT — Master Plan

> Documento canônico. Versão pós-cortes de overengineering: design intent completo para v1.0.0, com fases pré-launch enxutas e ativação trigger-based para hardening Enterprise.
> **Data:** 2026-05-22.

---

## 0. Princípios

1. **Vertical BR-first.** ANPD Art. 46 lidera; Drex/CBDC segundo; BCB 4893 suporte. Mercado-alvo: fintechs/bancos/seguradoras/cooperativas BR antes de qualquer expansão LATAM.
2. **PQC honesto.** Quantum-safe onde controlamos diretamente o protocolo. Onde dependemos de provider classical, declaramos em SECURITY.md (5 itens transitivos top-impact).
3. **Plano como artefato executável.** Toda promessa de controle vira código + integration test, não documento de spec longo. Planos servem ao próximo PR, não a auditores hipotéticos.
4. **Customer trust by architecture, not promise.** BYOK arquitetura para audit log preservada como design intent v1.0; ativada quando 1º Enterprise LOI demanda.
5. **Trigger-based provisioning.** Compliance avançada, ceremônia offline, sub-processadores caros, KMS providers múltiplos, payment processors duplos — ativados por customer-signal, não pré-emptivamente.
6. **SaaS antes de self-host.** Self-host apenas quando ANPD audit OR Enterprise SLA contracted explicitamente demanda.
7. **Defesa em profundidade contra nós mesmos.** Insider threat mitigado por arquitetura, ativado quando threat materializa (multi-tenant SaaS Phase 3+).

---

## 1. Tese de produto

**CryptoCT** é uma plataforma de Cryptography Bill of Materials (CBOM) dev-first para fintechs e bancos brasileiros. Escaneia código + dependências e produz CBOM CycloneDX 1.6 + SARIF identificando algoritmos cripto vulneráveis a quantum (Shor) e Grover, com policy engine schema-validado.

**Categoria:** criada por NIST CSWP 39 (dez/2025) + FIPS 203/204/205. Janela first-mover: 6-10 meses (IBM CBOMkit, Anchore Syft, GitHub Advanced Security, Snyk todos com roadmaps).

**Modelo:** open core (CLI Apache 2.0) + paid (GitHub App + SaaS dashboard + Enterprise).

**Tagline:**
> "ANPD Art. 46 + Drex exigem que você inventariar sua criptografia. CryptoCT é LGPD-nativo para o data plane de clientes; payments e error tracking são BR-resident."

Tagline NÃO usa "end-to-end quantum-safe".

---

## 2. Posicionamento regulatório (ordem importa)

1. **ANPD Art. 46 LGPD** + Resolução CD/ANPD 15/2024 (regulamento de fiscalização) — controles criptográficos como medida obrigatória de segurança
2. **Drex/CBDC do Banco Central** — cripto-agilidade necessária para participantes do ecossistema
3. **Resolução CMN 4.893/2021 + Resolução BCB 85/2021** — cyber-resilience bancária (suporte transitivo via vendor due diligence; CryptoCT é vendor, não entidade supervisionada)
4. **CVM Resolução 35** — gestores de recursos
5. **PCI-DSS v4** — bandeiras (Stone, PagSeguro, Cielo)
6. **ISO 27001:2022** + Annex A.10 (crypto) — trigger-based (customer LOI)
7. **SOC 2 Type II** — trigger-based (mercado US/intl, customer LOI)

Documentos de mapeamento em `docs/compliance/` (criados mês 1):
- `anpd-art46-mapping.md`
- `drex-crypto-agility.md`
- `bcb-4893-vendor-package.md` — Resolução CMN 4.893/2021 + Res. BCB 85/2021 vendor-due-diligence package: MSA right-to-audit clause + SOC 2 Type II roadmap + sub-processor list com LGPD Art. 33 attestation + pen-test summary. Tier-1 (Stone/Itaú/BTG) vendor-onboarding artifact set — não mapping (vendor não é entidade supervisionada).

---

## 3. Arquitetura

### 3.1 Phase 1-2 (current execution — Sigstore-keyless, single-tenant)

```
Customer dev laptop
    pqcheck CLI (Sigstore-keyless verified releases)
            │
            ▼
GitHub App cbom-diff (Phase 2)
    Cloudflare Workers (webhook verify + enqueue)
            │ TLS 1.3 hybrid X25519MLKEM768
            ▼
    AWS Lambda sa-east-1 (scan + CBOM diff PR comment)
    RDS sa-east-1 (per-installation row isolation simples)
    S3 sa-east-1 (CBOM storage)
    Sigstore Rekor (single anchor audit log)
```

### 3.2 Phase 3-4 design intent (trigger: ARR > R$ 800k OR 1º Enterprise LOI)

```
TIER 0 — Customer environment
    pqcheck CLI + customer KMS BYOK para K-audit-tenant
            │ TLS 1.3 + X25519MLKEM768 + Sigstore Rekor verification
            ▼
TIER 1 — Cloudflare edge (CONTROL PLANE, stateless)
    Workers + Turnstile
            │ Cloudflare Tunnel + mTLS hybrid PQC + AWS PrivateLink
            ▼
TIER 2 — AWS sa-east-1 (DATA PLANE)
    API Server Go chi + ent com RLS-aware query interceptor
    Scanner Pool gVisor-sandboxed (Phase 3 ativação)
    PostgreSQL 16 RDS (RLS multi-tenant + SESSION-mode PgBouncer)
    S3 Object Lock Compliance (multi-KMS scattered deletion) — Phase 4
    CloudHSM (K-image, K-service) — Phase 4
            │ Air-gapped USB courier
            ▼
TIER 3 — Ceremony environment (Phase 4 trigger-based)
    Tails OS + dedicated hardware + 2×YubiHSM2 + 1×backup
    pqcheck-courier tool + outside witness
```

### 3.3 Threat model (top 8)

1. Customer source exfiltration via scanner pod escape (Phase 3+ mitigation via gVisor)
2. K-release forgery via Tails ISO compromise (Phase 4 mitigation via pinned ISO + dedicated HW)
3. Dependency injection via unpinned ranges (mitigation via uv.lock + go.mod hash check em CI)
4. Cross-tenant audit log forgery via RLS bypass (Phase 3 mitigation via SECURITY DEFINER + event trigger)
5. Self-hosted runner compromise (Phase 3 mitigation via broker pattern release signing)
6. Marketing claim cascade — Cloud Act + sub-processor exposure (mitigation via BYOK + disclosure)
7. Billing fraud via webhook replay (Phase 3 mitigation via nonce + timestamp window)
8. Customer account compromise → API key bulk export (Phase 3 mitigation via 2FA WebAuthn obrigatório em sensitive pages)

### 3.4 Residência field-by-field (LGPD compliance)

| Campo | Classificação | Armazenamento | Sub-processador |
|---|---|---|---|
| Código-fonte cliente | NUNCA persistido (hashes + AST node types); Phase 3 aggregate ingest redige CryptoFinding.evidence para `(hash_prefix, ast_node_kind, line_range)` — sem evidence raw saindo do customer env | N/A | Não |
| CBOM gerado | Confidencial cliente | S3 sa-east-1 + RDS sa-east-1 | Não |
| Webhook payload GitHub | Metadados | RDS sa-east-1 após handoff | Cloudflare DPA |
| OAuth token cliente | Sensível | RDS sa-east-1 client-side AES-256-GCM | Cloudflare DPA |
| Email/nome usuário | PII LGPD | RDS sa-east-1 client-side encrypted | Cloudflare DPA |
| API key (Argon2id + HMAC index) | Sensível | RDS sa-east-1 | Não |
| Logs operacionais (PII scrubbed) | Operacional | Sentry SaaS + Datadog (Phase 3); self-host quando ANPD demanda | Sentry/Datadog DPA |
| Audit log events | Critical (regulatory) | RDS append + Sigstore Rekor (Phase 3); BYOK customer KMS (Phase 4) | Rekor |
| Stripe customer (USD Enterprise) | LGPD + PCI-DSS | Stripe US | Stripe (Cloud Act disclosed) |

### 3.5 Cloud Act risk + mitigação

AWS Inc (US parent) e Cloudflare Inc (US parent) têm obrigação CLOUD Act mesmo para dados em sa-east-1.

**Mitigação:**
1. **BYOK arquitetura** (Phase 4): Audit log encriptado client-side com chave customer-controlled. AWS produz ciphertext criptograficamente inútil sob CLOUD Act.
2. **Customer data minimization** (Phase 1+): Source code NUNCA persistido.
3. **Disclosure explícita**: `docs/compliance/sub-processor-disclosure.md` enumera Cloud Act risk.

---

## 4. Stack tecnológico

### 4.1 CLI (`pqcheck`)

| Camada | Escolha | Notas |
|---|---|---|
| Linguagem | Python 3.12+ | Iteração rápida, ecossistema AppSec |
| CLI framework | Typer 0.15 | Tipagem + autocompletion |
| Parser AST | tree-sitter (Java, Go) + ast stdlib (Python) | Pragmatismo |
| Dep tree | `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `requirements.txt`, `pyproject.toml` (PEP 621 + PEP 735), `uv.lock`, `go.mod` (via `tools/modfile-parser` Go helper), `go.sum`, `pom.xml` direto | Maven effective-pom = Phase 3 |
| Schema CBOM | `cyclonedx-python-lib` pinned via `uv.lock` | CycloneDX 1.6 |
| Output | Rich + JSON + SARIF 2.1.0 | GitHub Code Scanning compat |
| Política | `pqcheck-policy-v1.yaml` schema-validado + `--policy` flag | Phase 3 = auto-relax + CHANGELOG-lint |
| Severity | `severity = base × confidence_band` | LOW <0.5 demote 2; MED 0.5-0.8 demote 1; HIGH keep |
| Distribuição | PyPI + cibuildwheel 3-platform (Linux x86_64 + macOS x86_64 + macOS arm64); aarch64 Linux + Windows = v0.3+ | |
| Assinatura release | Sigstore keyless | ML-DSA-65 sidecar via broker pattern = Phase 3 |
| Testing | pytest 8 + hypothesis | Coverage > 85% |
| Lint/format | ruff + mypy strict | Type safety |

### 4.2 Backend SaaS (Phase 2-3+)

| Camada | Phase 2 (GitHub App) | Phase 3 (Dashboard) | Phase 4 (Enterprise) |
|---|---|---|---|
| Runtime | Cloudflare Workers + AWS Lambda | ECS Fargate + AWS GuardDuty | EKS + Falco community ruleset |
| Linguagem | TypeScript (Workers) + Go | Go 1.24+ chi + huma + ent | + custom Falco rules |
| ORM tenant isolation | per-installation row WHERE | ent query interceptor RLS-aware + PgBouncer SESSION mode | + scanner pod gVisor |
| Auth | GitHub App JWT RS256 | WebAuthn passkey + OIDC (Auth0/Clerk) | + SAML/SCIM + self-host Dex |
| Crypto library | Web Crypto + stdlib | + `crypto/mlkem` stdlib Go 1.24 | + Cloudflare CIRCL pinned |
| Logs | Cloudflare Workers logs (24h scrub) | Sentry SaaS + Datadog com DPA | Self-host Loki/Tempo/Grafana se ANPD demanda |
| Errors | Sentry SaaS PII allowlist | Sentry SaaS | GlitchTip self-host (se ANPD) |
| Queue | Cloudflare Queues | + AWS SQS | + NATS JetStream |
| Service-to-service | Webhook HMAC verify | mTLS hybrid PQC | + certificate pinning |
| Audit anchor | N/A | Sigstore Rekor single | + 3-of-3 quorum (Rekor + 2× RFC 3161 TSA) |

### 4.3 Frontend dashboard (Phase 3)

- Next.js 15 App Router + React 19 + TypeScript 5.6 strict
- shadcn/ui + Radix + Tailwind CSS 4
- TanStack Query v5 + Server Components
- WebAuthn via @simplewebauthn/browser
- CSP nonces strict + HSTS preload + COOP same-origin + COEP require-corp
- Vercel SP edge (assets only) com API direct para sa-east-1 via Tunnel

### 4.4 GitHub App (`cbom-diff`) — Phase 2

| Camada | Escolha |
|---|---|
| Runtime | Cloudflare Workers + AWS Lambda backend |
| Framework | Hono |
| GitHub SDK | @octokit/app + @octokit/webhooks com nonce + timestamp window 5min |
| Storage | D1 rate-limit; CBOMs em RDS sa-east-1 |
| PR comments | bleach allowlist HTML subset antes de render |
| Ownership check | Verify webhook installation includes target repo_ids |

### 4.5 Infraestrutura

| Camada | Phase 1 | Phase 2-3 | Phase 4 |
|---|---|---|---|
| Cloud edge | — | Cloudflare Workers stateless | + Turnstile anti-bot |
| Cloud stateful | — | AWS sa-east-1 (ECS Fargate + RDS + S3) | + EKS + CloudHSM |
| Container | Distroless pinned SHA-256 | + readonly rootfs | + gVisor sandbox + seccomp |
| Network policy | — | VPC endpoints + security groups | + zero-egress NetworkPolicy scanner |
| IaC | — | Terraform + tfsec | + custom Falco rules |
| Secrets | GitHub Secrets | + AWS Secrets Manager | + sops PQC para GitOps |
| CI/CD | GitHub Actions (default runners) | + ephemeral self-hosted sa-east-1 build tier | + signing-tier broker isolated |
| Image signing | Sigstore keyless | + ML-DSA-65 sidecar via broker pattern | + cibuildwheel 5-platform |
| Monitoring | — | Sentry SaaS + Datadog/Honeycomb DPA | Grafana self-host se ANPD demanda |
| Audit log | — | Sigstore Rekor single anchor | + multi-KMS scattered + Object Lock Compliance 7y + triple anchor |

### 4.6 Pagamento e billing

| Phase | Setup |
|---|---|
| Phase 1-2 | Stripe US only (USD) — DPA aceito por ANPD via addendum LGPD |
| Phase 3 (após 3º BR customer pedir Pix) | + Asaas BR (BRL Pix recurring) |
| Phase 4 | + Lago self-hosted se usage-based pricing demandar |
| NF-e BR | Manual até 20+ faturas/mês; NFE.io/Omie depois |

LTDA BR inicial; flip Cayman/Delaware pré-Series A.

---

## 5. Fases do projeto

### Fase 0 — Setup mínimo (Sem 0-1, ~1 semana)

- LTDA SP + CNPJ
- DPO fractional contratado (LGPD Art. 41 mandatory)
- Repos GitHub `cryptoct/pqcheck` (público) + `cryptoct/platform` (privado SSO+2FA)
- Domínios: cryptoct.com, cryptoct.com.br, pqcheck.dev
- PyPI handle `pqcheck`, Docker Hub `cryptoct/pqcheck`, npm `@cryptoct/cli`, GitHub org `cryptoct`
- README.md + SECURITY.md + LICENSE (Apache 2.0)
- CI básico: lint + tests + coverage

**Total:** ~5-10 engineer-days + 2 governance-days.

### Fase 1 — pqcheck CLI MVP (Sem 1-6, revisado)

Detalhe em `03-phase1-pqcheck-cli.md` (timeline re-baselined para 4-6 semanas com 2 founders FT; original "Sem 1-3" otimizava sobre tree-sitter ABI setup + cibuildwheel cross-platform + 8 lockfile parsers).

**Critérios de aceite v0.1.x developer preview:**
- `pip install pqcheck` (3-platform cibuildwheel: Linux x86_64 + macOS x86_64 + macOS arm64)
- `pqcheck scan ./repo --policy pqcheck-policy-v1.yaml` gera CBOM CycloneDX 1.6 + SARIF
- Schema validation CycloneDX 1.6 passa em CI
- Detecta RSA, ECDSA, DH, AES, SHA, MD5, 3DES em Java, Python, Go
- Lockfile parsers: poetry.lock, Pipfile.lock, pdm.lock, requirements.txt, pyproject.toml (PEP 621 + PEP 735), uv.lock, go.mod (via modfile-parser), go.sum, pom.xml direto
- Severity = base × confidence_band
- `--policy`, `--strict`, `--fail-on policy` flags
- Sigstore keyless signed releases
- DPIA + ROPA published em docs/compliance/

### Fase 1.5 — Policy engine + telemetry (Sem 3-4)

- `pqcheck-policy-v1.yaml` + JSON Schema publicados em docs.cryptoct.com
- `--policy` flag emite SARIF `properties.policy_id`
- 10-repo corpus benchmark (não 50 ainda; expandir conforme adoção)
- Self-audit dogfood source

### Fase 2 — GitHub App `cbom-diff` (Sem 5-7)

- App instalável via Marketplace
- Webhook PR processa em < 30s via Cloudflare Workers + AWS Lambda backend
- PR comment com CBOM diff sanitized
- Per-installation row isolation (não RLS multi-tenant ainda)
- Free tier: 1 repo público; paid: R$ 250/dev/mo (Stripe; Pix quando 3º customer pedir)
- 99.5% uptime SLO + status page

### Fase 3 — SaaS Dashboard (Mês 4-6, gating: ARR > R$ 800k run-rate OR Series Seed signed)

Ativa:
- WebAuthn passkey + OIDC (Auth0/Clerk)
- Multi-repo connect GitHub/GitLab/Bitbucket
- PostgreSQL RLS multi-tenant (ent query interceptor + PgBouncer SESSION mode)
- ECS Fargate + AWS GuardDuty + CloudTrail (sem EKS+Falco ainda)
- Sigstore Rekor audit log single anchor
- Sentry SaaS + Datadog/Honeycomb com DPA (sem self-host Loki/Tempo/Grafana ainda)
- ML-DSA-65 sidecar via broker pattern release signing (`circl-bridge` introduced agora)
- PagerDuty + on-call rotation founders (R$ 2-5k/mês opex)
- LGPD: data export 1-click; delete 30d com Art. 16 I carve-out para audit (cumprimento de obrigação legal/regulatória pelo controlador)
- Annual pen-test externo
- Bug bounty Intigriti activate
- Per-org permission scope dentro do tenant

### Fase 4 — Enterprise (Mês 7-12, trigger: 1º Enterprise LOI assinado)

Ativa **apenas quando customer LOI demanda**:
- K-release ceremônia (Tails + 2×YubiHSM2 + 1×backup + outside witness + cartório SP) — 5-20 eng-days
- BYOK adapter AWS KMS + customer pubkey export (Vault/Azure KV/on-prem HSM = on-demand) — 5-10 eng-days
- Audit log triple anchor 3-of-3 (Rekor + 2× RFC 3161 TSA) — 5-8 eng-days
- Multi-region S3 sync per-insert + S3 Object Lock Compliance multi-KMS scattered deletion — 8-13 eng-days
- Scanner pod gVisor sandbox + nsjail mvn sub-sandbox + zero-egress NetworkPolicy + seccomp — 7-10 eng-days
- EKS + Falco community ruleset + Tetragon eBPF (custom Falco rules apenas se security eng hired) — 5-8 eng-days
- Self-hosted runner ephemeral 1-job-per-VM + signing-tier isolated — 5-7 eng-days
- Tails ISO pinning + dedicated hardware + cofre bancário + secureerase NVMe — 1 eng-day + 1 gov-day
- Helm chart + Docker Compose self-hosted
- SAML 2.0 + SCIM provisioning
- Audit trail Merkle exportável + `pqcheck audit-verify --rekor-witness --tsa-witness --kms-pubkey customer.pub`
- Air-gapped deployment
- SOC 2 Type II observation window inicia (audit paid pelo deal)
- ISO 27001 stage 1-2

**Total Fase 4 ativação:** 36-77 eng-days + 5 gov-days, **financiados pelo 1º Enterprise LOI**.

### Fase 5 — Expansão (Mês 13+)

- JS/TS, Rust, C#/.NET, Kotlin, Swift parsers
- Runtime scanner eBPF
- IDE plugins
- Marketplace de regras community + verified
- LATAM piloto (México, Colômbia, Chile, Argentina)
- Decisão: migração para 100% BR-resident provider (Locaweb/Tivit/Algar) se ANPD audit demanda

---

## 6. Compliance e budget

### 6.1 Compliance OpEx 18 meses (revisto + full burn)

#### 6.1.1 Compliance-only line items

| Item | USD baseline | USD high | Trigger |
|---|---|---|---|
| DPO fractional + DPIA + ROPA + LGPD docs | 12.000 | 20.000 | Mandatory mês 1 |
| Legal: privacy, contratos, NDA, MSA templates | 15.000 | 30.000 | Mandatory mês 1 |
| Vanta ou Drata 18m | 18.000 | 28.000 | Phase 3 (seed signed) |
| Pen-test externo annual | 15.000 | 25.000 | Phase 3 launch |
| Compliance ops fractional | 20.000 | 35.000 | Phase 3 |
| ISO 27001 BR | 35.000 | 55.000 | Phase 4 (customer LOI) |
| SOC 2 Type II premium PQC | 55.000 | 90.000 | Phase 4 (customer LOI; paid via deal close) |
| Fractional vCISO | 18.000 | 30.000 | Phase 3+ |
| Bug bounty Intigriti (platform fee; payouts variáveis adicionais ~USD 10-30k/yr) | 5.000 | 15.000 | Phase 3 activate |
| PagerDuty | 1.500 | 4.000 | Phase 3 |
| Defensive squatting (4 registries + 3 domains) | 200 | 500 | Mês 1 |
| **Sub-total compliance 18m (Phase 0-3)** | **104.700** | **187.500** | |
| **Sub-total compliance 18m (com Phase 4 ISO/SOC 2)** | **194.700** | **332.500** | Phase 4 portion paid via deal |

#### 6.1.2 Full burn line items (P0 — não orçados em §6.1.1)

| Item | USD baseline | USD high | Notas |
|---|---|---|---|
| Founder compensation (2 founders × USD 3-5k/mês × 18m) | 108.000 | 180.000 | Survival assumption mínima; rever para seed math |
| AWS sa-east-1 baseline (Phase 1-2 ~USD 200/mês; Phase 3 ramp USD 0.8-2.5k/mês) | 12.000 | 35.000 | Inclui RDS Multi-AZ + ECS Fargate + S3 + KMS Phase 3 |
| Cloudflare Workers + Tunnel + Turnstile (Phase 3) | 1.500 | 3.500 | |
| CloudHSM Phase 3 (USD 1.45/hr × 2 HSMs × 6m) | 12.500 | 12.500 | Phase 3 hard cost; ~R$ 60k/6m |
| Bancário/contabilidade BR LTDA (IRPJ + ISS + folha contábil ~R$ 2-5k/mês) | 7.200 | 18.000 | |
| Equipment Phase 4 trigger (YubiHSM2 ~USD 700 × 3-5 + Tails ThinkPad ~USD 1.5k + cofre bancário fee) | 3.700 | 6.000 | Diferido até Phase 4 trigger |
| Bug bounty payouts (Phase 3+) | 10.000 | 30.000 | Variável; reserva |
| **Sub-total full burn 18m** | **154.900** | **285.000** | |

#### 6.1.3 Totais consolidados

| Total | USD baseline | USD high | R$ a 5.0 |
|---|---|---|---|
| **Phase 0-3 compliance + full burn** | **259.600** | **472.500** | **R$ 1.298M - R$ 2.363M** |
| **+ Phase 4 trigger ISO/SOC 2 (paid via deal)** | **349.600** | **617.500** | **R$ 1.748M - R$ 3.088M** |

**Survival branch implicação:** ARR R$ 800k-1.2M cumulative 18m **não cobre** burn R$ 1.3-2.4M. Survival math em §9 requer founder salary skip (R$ 540-900k) OU runway extension via bridge financing.

### 6.2 ARR re-segmentada por gates

| Gate | Mês | Pré-requisito | Pricing | ACV |
|---|---|---|---|---|
| G0: PoC OSS | 0-6 | CLI público + GitHub App | CLI free + App R$ 250/dev/mo | $15-40k |
| G1: Vanta + annual pen-test | 6-12 | Seed signed | Starter SaaS R$ 2.5-12k/mo | $50-150k |
| G2: ISO 27001 in progress | 12-15 | LOI Enterprise → triggers ISO/SOC 2 | Growth SaaS R$ 12-25k/mo | $150-300k |
| G3: SOC 2 Type II report | 15-18 | Customer LOI financed audit complete | Enterprise R$ 250k-1.5M/yr | $250-1500k |

### 6.3 Cenários ARR 18 meses

| Cenário | Probabilidade | ARR | Logos |
|---|---|---|---|
| Base | 75% | R$ 1.5-3.5M | 8-12 |
| Otimista | 15% | R$ 4-6M | 12-15 |
| Survival | 10% | R$ 0.8-1.2M | 6-8 |

### 6.4 Audit log architecture

**Phase 3:**
```
Event → INSERT via SECURITY DEFINER stored procedure (não exposed to app role)
     → audit_outbox (DBA UPDATE/DELETE blocked via PG event triggers)
     → Background Merkle worker (hourly cron)
     → Sigstore Rekor (single anchor)
     → RDS append + S3 sa-east-1 (single region)
```

**Phase 4 ativação (1º Enterprise LOI):**
```
+ Multi-region S3 sync per-insert
+ Customer KMS BYOK sign Merkle root
+ Triple anchor: S3 Object Lock Compliance 7y (multi-KMS scattered) + Rekor + 2× RFC 3161 TSA (3-of-3 quorum)
+ Long-term archive: SLH-DSA-SHA2-128s assinatura mensal
+ Customer independent verification via `pqcheck audit-verify --quorum-required 3`
```

---

## 7. Top risks (consolidado, era R1-R30)

| # | Risco | Severity | Mitigação | Owner |
|---|---|---|---|---|
| TR1 | Competitor catch-up (Snyk/IBM/Anchore lançam CBOM beta H2 2026) | Alta/Crítico | Vertical BR + ANPD/Drex focus; tripwire pivot policy engine | Founders |
| TR2 | Adoção lenta CLI (sem stars + downloads em 8 semanas pós-launch) | Alta/Alto | HN launch + outreach BR + DevSecOps community + ANPD/Febraban events | Founders |
| TR3 | Hire AppSec senior BR difícil | Alta/Alto | Community + equity heavy + LATAM remoto + fractional CISO interim | Founders |
| TR4 | Seed round slipa mês 4 sem term sheet | Média/Alto | Survival plan §9: R$ 800k-1.2M ARR floor; bootstrapped indefinido como fallback | Founders |
| TR5 | Cofounder não materializa | Média/Alto | Ceremony degraded-mode pattern documentado para Phase 4 ativação | Founders |
| TR6 | Vazamento dados cliente (Phase 3+) | Baixa/Crítico | gVisor sandbox + zero-egress + BYOK + bug bounty | Sec |
| TR7 | Supply-chain compromise release | Média/Crítico | Sigstore + Rekor + reproducible builds + (Phase 3+) ML-DSA-65 sidecar broker pattern | Eng + ops |
| TR8 | Typosquat PyPI/npm/Docker | Alta/Médio | Defensive registrations dia 1 (4 registries + 3 domains); Socket.dev/Phylum monitor | Founder ops |
| TR9 | ANPD endurece Art. 46 enforcement | Média/Alto | Stack já BR-resident; sub-processador alternativas pré-mapeadas; DPIA + ROPA atualizados | Compliance |
| TR10 | Cloud Act exposure (AWS US-parent) | Crítico (Phase 4) | BYOK arquitetura para audit (zero-knowledge); customer data minimization; explicit transferência internacional disclosure (LGPD Art. 33 onde sub-processador US-parented dispara) | Compliance + Sec |
| TR11 | False positive rate alto em corpus customer | Alta/Alto | severity × confidence_band; corpus público crescente; manual policy adjust via PR | Eng |
| TR12 | GitHub App JWT RS256 (limitação upstream) | Alta/Médio | TLS PQC outer + ML-DSA-65 payload sig em PR comments (Phase 3) | Eng |

---

## 8. Cronograma (consolidado)

```
Sem 0-1 (Mai 2026) — Setup (5-10 eng-days)
├── LTDA SP + DPO fractional
├── 4 registries + 3 domains claim
├── README + SECURITY.md + LICENSE
└── Repos + CI básico

Sem 2-4 (Mai-Jun 2026)
├── Fase 1 CLI MVP — Python infra, parsers, detectors, 9 lockfile parsers
├── v0.0.1 unsigned dev preview (Sem 2)
└── v0.1.x developer preview (Sem 4, Sigstore keyless, 3-platform wheels)

Sem 5 (Jun 2026)
├── DPIA + ROPA published
└── Corpus 10-repo benchmark + precision evaluation (fallback `--strict` opt-in se < 0.85)

Sem 6 (Jun 2026)
├── HN Show HN launch (apenas após DPIA + 4 ADRs + tails-pinning.yaml committed)
└── 3-6 PoC OSS conversations iniciadas

Sem 7-10 (Jun-Jul 2026)
├── Fase 2 GitHub App MVP (Cloudflare Workers + AWS Lambda)
└── Marketplace listing aprovado

Mês 2-3 (Jul-Ago 2026)
├── Decisão: Sentry SaaS + Datadog/Honeycomb DPA (não self-host)
├── Stripe-only billing
├── Hire: 1 SDR BR + 1 AppSec sr (se ARR > R$ 500k run-rate)
└── Primeiro PoC pago G1

Mês 4-6 (Set-Nov 2026) — Fase 3 ativação
├── SaaS Dashboard + RLS multi-tenant + ECS Fargate
├── ML-DSA-65 sidecar broker pattern release signing
├── Series Seed: USD 2-3M (Quantonation + Canary/Monashees/Astella)
├── Vanta/Drata signup
├── Annual pen-test externo
├── Bug bounty Intigriti activate
└── PagerDuty + on-call rotation

Mês 7-9 (Dez 2026 - Fev 2027)
├── Quarterly tabletop drill
└── 6-10 logos G1-G2

Mês 10-12 (Mar-Mai 2027) — Fase 4 trigger
├── Se 1º Enterprise LOI signed: ativar ceremônia + BYOK + triple-anchor + gVisor + EKS
├── ISO 27001 stage 1-2 (financed by LOI)
├── SOC 2 Type II observation window
└── v1.0.0 production release

Mês 13-18 (Jun-Out 2027)
├── ISO 27001 cert
├── SOC 2 Type II report
├── Primeiros 1-2 Tier-1 enterprise G3
├── Series A: USD 8-15M (NightDragon, Forgepoint, Quantonation follow-on)
└── ARR base R$ 2.5-4.5M
```

---

## 9. Plano de contingência cofounder-only (survival)

**Trigger:** mês 4 sem term sheet seed OR sem AppSec hire confirmada com data início < 30d.

**Plano:**
- Mês 0-6: CLI + GitHub App publicados; sinal de tração via stars + downloads + community talks. **Founder salary skip mandatory** (ver §6.1.3) — survival assume USD 1.5-2k/mês living-cost mínimo por founder, não USD 3-5k baseline.
- Mês 6-12: PoCs OSS viram contratos Starter R$ 2.5-12k/mo via founder outbound; meta 8-15 clientes Starter = R$ 240-720k ARR run-rate end Y1
- Mês 12-18: GitHub App + Starter sustentam R$ 800k-1.2M ARR; founders + 2 (designer + AE fractional); sem Phase 4 ativação, sem Enterprise tier
- Mês 12 re-avaliação: ARR > R$ 1M e crescimento > 15% MoM por 3 meses → tentar seed menor (USD 800k-1.5M); senão bootstrapped indefinido ou exit

**Survival cash math (P0 — revisado pós-§6.1):** Burn 18m mínimo (founder skip + sem Phase 4) ≈ R$ 1.0-1.4M (compliance R$ 525k + founder living-cost R$ 320k + AWS+infra R$ 80k + bancário/contábil R$ 60k). Survival ARR cumulative 18m com ramp linear de R$ 0 a R$ 800k-1.2M run-rate end-Y1.5 ≈ R$ 600-900k cumulative. **Gap R$ 200-600k requer bridge OR ARR ramp J-curve (não-linear) OR founder living-cost subsidy externo.**

**Ceremony degraded-mode** (single founder ativo, apenas se Phase 4 ativada): time-locked single-signer com 7-day Rekor witness delay (ver `02-quantum-safe-crypto-policy.md §6.4`).

---

## 10. Estrutura monorepo

```
CryptoCT/
├── README.md
├── LICENSE                          # Apache 2.0 CLI
├── SECURITY.md                      # PGP key + Transitive PQC Risk (5 items)
├── CODEOWNERS                       # Protected paths
├── pqcheck-policy-v1.yaml           # POLICY ARTIFACT
├── pqcheck-policy.schema.json
├── .github/
│   └── workflows/
│       ├── cli-ci.yml
│       ├── cli-policy-check.yml
│       ├── cli-release.yml          # Sigstore keyless Phase 1; broker pattern adicionado Phase 3
│       └── pqc-self-scan.yml
├── docs/
│   ├── plans/                       # canonical plans
│   ├── adr/                         # ADRs para decisões arquiteturais
│   │   ├── 0001-mofn-quorum-rationale.md     # K-release 2-of-3 (Phase 0 P0)
│   │   ├── 0002-tls-root-quorum-rationale.md # K-tls-root 3-of-5 (Phase 0 P0)
│   │   ├── 0003-shamir-ram-opsec.md          # Shamir-RAM-reconstruction mitigation (Phase 0 P0)
│   │   └── 0004-ceremony-trust-root.md       # Tails project signing-key residual risk (Phase 0 P0)
│   ├── compliance/
│   │   ├── anpd-art46-mapping.md
│   │   ├── drex-crypto-agility.md
│   │   ├── bcb-4893-vendor-package.md
│   │   ├── dpia-2026.md
│   │   ├── ropa-2026.md
│   │   └── sub-processor-disclosure.md
│   └── marketing/
│       └── launch-copy-guide.md
├── packages/
│   ├── pqcheck/                     # Phase 1 CLI Python
│   ├── cbom-diff-app/               # Phase 2 Workers + Lambda (criado Phase 2)
│   ├── api/                         # Phase 3 Go backend (criado Phase 3)
│   ├── scanner-svc/                 # Phase 3 Scanner pool (criado Phase 3)
│   └── dashboard/                   # Phase 3 Next.js
├── infra/
│   ├── terraform/                   # criado Phase 2
│   └── kubernetes/                  # criado Phase 4
└── tools/
    ├── modfile-parser/              # Go go.mod helper (Phase 1)
    ├── circl-bridge/                # Go ML-DSA helper (Phase 3+)
    └── pqcheck-courier/             # Tails toolkit (Phase 4+)
```

---

## 11. GTM (re-segmentado por gate)

### Canais Fase 1

- HN Show HN — semana 4
- Twitter/X DevSecOps + Crypto BR thread
- Reddit /r/netsec, /r/cryptography, /r/devsecops
- DevSecOps Brasil Slack
- LinkedIn AppSec BR outreach 50 leads
- OWASP SP/Rio + BSides SP + Mind the Sec + H2HC talks
- ANPD events 2026, Febraban Tech, CIAB FEBRABAN

### Canais Fase 2-3 segmentados

**G0 (mês 0-6) — SaaS fintechs não-reguladas:**
- Founders outbound → Loft, QuintoAndar, Pipefy, RD Station, Hotmart, Olist, Conta Azul, Pluga
- Target: 3-6 PoC paperwork signed

**G1 (mês 6-12) — mid-market:**
- SDR + founder dual outbound → Conta Simples, Cora, Trampolin, Cloudwalk, Liber Capital, Solfácil, Banco Modal, BMG
- Target: 2-4 contratos R$ 50-150k ACV

**G2 (mês 12-15) — Tier-2 fintech:**
- Founders + AE → Stone, PicPay, PagSeguro, BTG, Daycoval
- Target: 1-2 PoC pago R$ 150-300k

**G3 (mês 15-18+) — Tier-1 enterprise:**
- AE + Solutions Engineer → Nubank, Inter, C6, Mercado Pago, Itaú, Bradesco, Santander BR
- Target: 1-2 contratos R$ 250k-1.5M/yr — só se SOC 2 Type II report ready (financed by LOI)

### Pricing inicial

| Tier | BR (BRL via Pix em Phase 3) | Intl (USD via Stripe) |
|---|---|---|
| CLI | Free forever | Free forever |
| GitHub App | R$ 250/dev/mo | $50/dev/mo |

Adicionar tiers (SaaS Starter/Growth/Enterprise) conforme primeiros 5 paying customers pushback em pricing.

### VC mapping

| Round | Targets primários | Pré-requisito |
|---|---|---|
| Pre-seed | Maya Capital, Canary | LTDA BR |
| Seed (M4-6, USD 2-3M) | Quantonation (PQC lead), Kaszek (LATAM) | LTDA BR ou flip iminente |
| Series A (M15-18, USD 8-15M) | NightDragon, Sequoia LATAM, Forgepoint, a16z cyber | Cap-table flip Cayman/Delaware |

---

## 12. Next steps imediatos (próximas 72h)

- [ ] LTDA SP constituída + conta CNPJ
- [ ] Repos GitHub `cryptoct/pqcheck` (público) + `cryptoct/platform` (privado SSO+2FA enforced)
- [ ] Domínios: cryptoct.com, cryptoct.com.br, pqcheck.dev (~R$ 200/yr total) + keys.cryptoct.com DNS placeholder reservado
- [ ] PyPI handle `pqcheck` + Docker Hub `cryptoct/pqcheck` + npm `@cryptoct/cli` + GitHub org `cryptoct`
- [ ] Handles: Twitter/X `@cryptoct_pqc`, LinkedIn page `CryptoCT`, HN user
- [ ] AWS sa-east-1 + Cloudflare + GitHub Team accounts
- [ ] DPO fractional contratado para DPIA mês 1
- [ ] 4 ADRs criados em `docs/adr/`: 0001-mofn-quorum-rationale.md, 0002-tls-root-quorum-rationale.md, 0003-shamir-ram-opsec.md, 0004-ceremony-trust-root.md
- [ ] CODEOWNERS configured para `migrations/`, `pqcheck-policy*.yaml`, `tools/circl-bridge/`, `tools/pqcheck-courier/`
- [ ] `tails-pinning.yaml` stub committed (será co-signed pré-Phase 4 trigger)
- [ ] Iniciar Fase 1 CLI development

---

## 13. Referências cruzadas

- **Política cripto + key custody:** `02-quantum-safe-crypto-policy.md`
- **Implementação Fase 1:** `03-phase1-pqcheck-cli.md`
- **Operações de segurança + IR + compliance:** `04-security-operations.md`
