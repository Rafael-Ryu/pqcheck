# CryptoCT — Development Roadmap (Phase 1 → Phase 4)

> Roadmap de desenvolvimento puro: o que é construído, em qual ordem, com que dependências técnicas, em qual estado demo-able cada fase chega. **Apenas engenharia** — sem partes legais, econômicas ou de compliance regulatória externa. Para budget e regulação ver `01-master-plan.md` e `04-security-operations.md`.
>
> **Phase 0 foi removida como fase separada.** O que era "Phase 0" se decompõe em dois grupos: (a) pré-requisitos técnicos triviais que se resolvem em Day 0 de Phase 1 (~1h de trabalho — ver Pre-flight setup abaixo), e (b) preparação para a cerimônia Phase 4 (4 ADRs + `tails-pinning.yaml`) que vai para a janela "Phase 4 prep" mais adiante. Nada precisa de uma fase dedicada de 2 semanas.

---

## Visão geral

CryptoCT é construída em 4 fases. Cada fase tem **um marco de deploy concreto** (algo que termina publicado em algum lugar verificável) e **um trigger técnico falsificável** que permite ou bloqueia a próxima fase.

```
Phase 1 — pqcheck CLI (laptop)     [Sem 0-4]   → PyPI release v0.1.0 assinada Sigstore
Phase 2 — GitHub App                [Mês 2-3]   → GitHub App listada no Marketplace
Phase 3 — SaaS multi-tenant         [Mês 4-6]   → dashboard cryptoct.com em sa-east-1
Phase 4 — Enterprise hardening      [Mês 9-12]  → release cerimônia offline + BYOK live + triple-anchor
                                     (Phase 4 prep window Mês 8.5: 4 ADRs + tails-pinning ceremony)
```

Dependências fluem para frente apenas. Phase N+1 nunca pode começar sem Phase N entregue e deploy-verificado.

---

## Phase 1 — pqcheck CLI local (Sem 0-4)

**Objetivo:** entregar v0.1.0 publicada no PyPI, assinada Sigstore keyless, que escaneia repos locais e produz CBOM + SARIF + relatório validado contra policy YAML.

### Pre-flight setup (Day 0, ~1h)

Único trabalho que tecnicamente bloqueia o `pip install pqcheck` funcionar. Esses passos vão no Day 0 de Phase 1 e são parte da Sem 0 abaixo.

- [ ] Reclamar namespace PyPI `pqcheck` (15 min — pode falhar se já tomado; ter fallback `pqcheckio` pronto)
- [ ] Criar GitHub org `cryptoct` e repos públicos `cryptoct/pqcheck` + `cryptoct/cryptoct` (15 min)
- [ ] Initial commit: `pyproject.toml` + `LICENSE` (Apache-2.0) + `README.md` mínimo (PyPI requer LICENSE classifier) (20 min)
- [ ] Branch protection em `main` no GitHub repo settings (10 min)
- [ ] Reclamar Docker Hub + npm namespace (defensive squatting — paralelo, 10 min)

**Total: ~1h dos 2 fundadores em paralelo.** Por volta do almoço do Day 0, ambos estão escrevendo código.

> **Itens diferidos para Phase 4 prep** (não bloqueiam Phase 1): 4 ADRs P0 + co-assinatura `tails-pinning.yaml`. Ver seção "Phase 4 prep window" antes da seção Phase 4.

### Deliverables

| Módulo | Pacote/path | Conteúdo |
|---|---|---|
| **CLI entry** | `pqcheck/cli.py` | argparse + subcomandos: `scan`, `self-audit`, `verify-release` |
| **Policy engine** | `pqcheck/policy/` | YAML loader + schema (`pqcheck-policy-v1.yaml`) + 3 default policies BR-tuned (`br-bcb-conservative`, `br-drex-piloto`, `br-vendor-dd`) |
| **Detectors** | `pqcheck/detectors/` | `python_ast.py` (stdlib AST) + `go_treesitter.py` + `java_treesitter.py` (tree-sitter + JCE coalescer) |
| **Lockfile parsers** | `pqcheck/lockfile/` | 8 parsers: `pyproject_toml`, `uv_lock`, `go_mod`, `pom_xml`, `package_lock_json`, `gemfile_lock`, `cargo_lock`, `composer_lock` |
| **Findings model** | `pqcheck/finding.py` | pydantic models: `CryptoFinding`, `QuantumRisk` enum, `ConfidenceBand` enum + `severity = base × confidence_band` |
| **CBOM output** | `pqcheck/output/cbom.py` | CycloneDX 1.6 JSON via `cyclonedx-python-lib` ≥ 7.0.0 |
| **SARIF output** | `pqcheck/output/sarif.py` | SARIF 2.1.0 com control-character filter (não bleach) |
| **Self-audit** | `pqcheck/self_audit.py` | scanner pqcheck rodando contra suas próprias deps + ADR waiver registry leitor |
| **Precision benchmark** | `tests/precision/` | 10-repo corpus + harness; target ≥0.85; fallback `--strict` opt-in se eval falha |

### Build sequence (4-6 semanas; sem fase 0 dedicada, começa direto no código)

```
Sem 0 (Day 0 manhã: pre-flight setup ~1h)
  Sem 0 resto: começa código imediatamente
  Founder A: detector Python AST (3 dias) + lockfile parsers pyproject/uv/pom (2 dias)
  Founder B: policy schema + YAML loader (2 dias) + 3 default policies (2 dias)
  Both:      pyproject.toml completo + GitHub Actions skeleton + cibuildwheel config (1 dia, paralelo)

Sem 1:
  Founder A: detector Go tree-sitter (3 dias) + lockfile parsers go.mod/package-lock (2 dias)
  Founder B: CycloneDX 1.6 output + SARIF 2.1.0 output (3 dias) + Findings pydantic model (2 dias)

Sem 2:
  Founder A: detector Java tree-sitter + JCE coalescer (4 dias) + lockfile parsers Gemfile/Cargo/composer (1 dia)
  Founder B: CLI entry + arg parsing + verbose/quiet/strict flags (2 dias) + Sigstore release GitHub Action (2 dias)

Sem 3:
  Founder A: 10-repo precision corpus assembly + benchmark harness (3 dias) + first eval (1 dia)
  Founder B: self-audit CI gate (2 dias) + waiver ADR template + docs/security/waivers.md (1 dia)
  Both:      cibuildwheel matrix Linux x86_64 + macOS x86_64/arm64 (2 dias)

Sem 4:
  Founder A: precision tuning baseado em eval → if <0.85 → ship --strict opt-in (2 dias)
  Founder B: README final + examples/ folder + 3 demo repos públicos (2 dias)
  Both:      v0.0.1 dev preview no TestPyPI (1 dia) → v0.1.0 stable PyPI release (1 dia)
```

### Dependências

- **Pre-flight setup feito (~1h Day 0):** namespace PyPI + repo GitHub + LICENSE + branch protection
- **Externas:** Sigstore Fulcio + Rekor (services públicos); GitHub Actions OIDC; `cyclonedx-python-lib` ≥ 7.0.0; `tree-sitter` + grammars Python/Go/Java

### Cross-cutting durante Phase 1

- **Test suite:** pytest com ≥80% coverage no core (detectors, parsers, policy engine, output). Integration tests rodam contra os 3 demo repos.
- **CI pipeline:** GitHub Actions com matrix Python 3.10/3.11/3.12/3.13 + matrix OS Linux/macOS. `pqcheck self-audit` é gate obrigatório de release.
- **Release pipeline:** tag `v*.*.*` → GitHub Actions OIDC → Fulcio cert → wheel build cibuildwheel → Rekor sign → upload PyPI via `pypa/gh-action-pypi-publish` com Trusted Publishing (no API keys).
- **Documentação técnica:** README EN principal + `README.pt-br.md` espelho; SECURITY.md em EN com Transitive PQC Risk 5 itens; CONTRIBUTING.md com setup dev local.

### Demo-able state

```bash
$ pip install pqcheck
$ pqcheck scan ./meu-projeto --policy=br-bcb-conservative
✗ src/auth.py:42 - RSA-2048 (BANNED)
✓ src/aead.py:7  - AES-256-GCM (APPROVED)
CBOM:  ./cbom.cdx.json (47 components)
SARIF: ./pqcheck.sarif
```

- `cosign verify` consegue verificar a assinatura Sigstore do wheel
- README na PyPI exibe demo + badge Sigstore + badge precision
- Show HN launchable

### Trigger para Phase 2

3+ inbound requests para CI-integrated scan que CLI sozinha não satisfaz, **ou** 1 pilot conditional em CI integration. Sinais confirmatórios técnicos: PR de outsider mergeado; ≥5 stars; issue request explícita por GitHub App.

---

## Phase 2 — GitHub App (Mês 2-3, trigger-based)

**Objetivo:** entregar GitHub App nativa que escaneia PRs automaticamente, faz upload de SARIF para GitHub Code Scanning, e devolve CryptoFinding redigido (nunca evidence raw) para CryptoCT-managed infra.

### Deliverables

| Componente | Stack/path | Conteúdo |
|---|---|---|
| **Webhook receiver** | Cloudflare Workers (Workers KV para idempotência) | Recebe PR/push events GitHub; valida signature + nonce + monotonic-clock + 10min window (EXC-001 compensating control) |
| **Scan executor** | AWS Lambda sa-east-1 (Python container) | Clona PR ref shallow; roda `pqcheck scan`; emite findings; descarta source code do filesystem em < 60s |
| **Wire format** | `pqcheck/wire/` | spec: somente `hash_prefix` (8 bytes), `ast_node_kind`, `line_range`. **Evidence raw nunca atravessa rede.** Schema versionado v1 (`application/vnd.cryptoct.findings.v1+json`) |
| **GitHub Check Run API** | Lambda → GH | Posta finding summary como Check Run; SARIF upload via Code Scanning API |
| **Payload signing** | ML-DSA-65 (server-side sign via CIRCL-Go bridge ou liboqs broker) | Sig em payload outbound (compensating control para JWT RS256 GitHub upstream limitation EXC-001) |
| **Marketplace listing** | GitHub Marketplace | App descritor + screenshots + permissions request scope + pricing tier descritor |

### Build sequence (6-8 semanas)

```
Mês 2 Sem 1-2:
  Founder A: Wire format spec v1 + JSON Schema + redaction tests (3 dias)
  Founder B: AWS account setup (sa-east-1) + IAM roles + Lambda skeleton (3 dias)
  Both:     ARN naming + tags (1 dia)

Mês 2 Sem 3:
  Founder A: Cloudflare Workers webhook receiver + signature validation (4 dias)
  Founder B: Lambda scan executor: shallow clone + pqcheck invoke + findings emit + temp cleanup (4 dias)

Mês 2 Sem 4:
  Founder A: GitHub App registration + permissions request scope + OAuth flow (3 dias)
  Founder B: Check Run API + SARIF upload via Code Scanning API (3 dias)
  Both:     End-to-end test: clone-test-fintech-repo → PR → scan → Check Run visible (1 dia)

Mês 3 Sem 1:
  Founder A: ML-DSA-65 sign-server (CIRCL-Go bridge vs liboqs broker decision + impl) (5 dias)
  Founder B: Workers KV idempotência + replay attack tests (3 dias)

Mês 3 Sem 2:
  Both: Penetration self-test: replay attacks, payload tampering, GitHub App impersonation, race conditions
  Founder B: Customer-facing technical docs (setup guide, permissions explainer)
  
Mês 3 Sem 3:
  Founder A: Marketplace listing submission (revisão GitHub ~5-15 dias úteis)
  Founder B: First 3 pilot customers onboarding técnico (manual, hand-holding)
```

### Dependências

- **Phase 1 publicada e estável** — `pqcheck` v0.1.x precisa rodar dentro do Lambda container
- **GitHub App registration aprovada** (público marketplace listing requer revisão GH)
- **AWS account sa-east-1 ativada** com IAM
- **Cloudflare account com Workers paid plan** (free tier não tem KV adequado para idempotência)
- **ML-DSA-65 implementation decision:** CIRCL-Go bridge via cgo OR liboqs broker subprocess — decidido em ADR Phase 2

### Cross-cutting durante Phase 2

- **Wire format é contrato externo:** mudança = breaking change. Versionar com `Accept: application/vnd.cryptoct.findings.v1+json`.
- **Source-never-persisted é invariante:** integration test obrigatório `test_lambda_purges_clone_within_60s`. Failover: Lambda timeout 60s + EBS-less ephemeral storage.
- **Audit log nesta fase é Lambda CloudWatch Logs:** sem persistência tamper-evident ainda; documentado em ADR como decisão consciente.
- **CI/CD pipeline expandido:** GitHub Actions → `wrangler` (Cloudflare deploy) + `sam-cli` (Lambda deploy) + `gh api` (App Marketplace version bump).

### Demo-able state

- GitHub App listada no Marketplace (público)
- Customer instala app → adiciona em repo → abre PR → Check Run aparece em ≤ 60s com findings redigidos + SARIF upload visível em Code Scanning tab
- Replay de webhook anterior é rejeitado (idempotência via Workers KV)
- Payload tampering é detectado (ML-DSA-65 sig fail)

### Trigger para Phase 3

≥20 customers ativos no GitHub App + ≥3 pedidos explícitos por dashboard ou histórico cross-time, **ou** financing event que justifique investir em multi-tenant SaaS.

---

## Phase 3 — SaaS multi-tenant (Mês 4-6, trigger adoption ou financing)

**Objetivo:** entregar dashboard SaaS multi-tenant em `cryptoct.com` com histórico de scans, comparativos cross-time, e RLS-protected isolation.

### Deliverables

| Componente | Stack/path | Conteúdo |
|---|---|---|
| **Database** | PostgreSQL 16 em RDS sa-east-1 | RLS multi-tenant; roles `cryptoct_app` (NOSUPERUSER + RLS-enforced) e `cryptoct_admin` (BYPASSRLS, vault-locked); `SET LOCAL tenant_id` per request |
| **Connection pooling** | PgBouncer SESSION mode | Pool 50 conexões; isolar long-running scan ingest em pool separado |
| **Tenant interceptor** | ent ORM TenantInterceptor (Go) | Auto-inject `SET LOCAL tenant_id` em todas as transactions |
| **Backend service** | Go + ent ORM em ECS Fargate sa-east-1 | API REST + WebSocket para live findings stream |
| **Frontend** | React + TypeScript + Tailwind | Dashboard único view: repos × scans × findings × policies |
| **Auth** | OAuth GitHub (delegado) + magic link email | No password storage |
| **Ingest endpoint** | `/v1/findings` | Rejeita evidence raw explicitamente; test obrigatório `test_ingest_rejects_raw_evidence` |
| **K-service signing** | ML-DSA-65 sidecar (broker pattern) | Server-side audit signatures em findings persistidos; key em AWS KMS asymmetric (não exportável) |
| **K-service rotation register** | `https://keys.cryptoct.com/k-service-rotation.json` | Publicação assinada por K-image; obriga em acceptance Phase 3 (gap D-6 resolvido) |
| **Observability** | Sentry SaaS (PII scrub config) + Datadog OR Honeycomb | Backend slog scrub middleware + Sentry beforeSend hook |
| **Monitoring** | GuardDuty + CloudTrail + EventBridge | Alert on `SET ROLE cryptoct_admin`; alert on BYPASSRLS usage; alert on `SECURITY DEFINER` calls outside whitelist |
| **OPSEC runbook técnico** | `docs/runbooks/cryptoct_admin.md` | Vault credential location; MFA hardware (YubiKey 5C); 4-eyes for any production session; audit obrigatório no fim da sessão |
| **CODEOWNERS gates** | `.github/CODEOWNERS` | `/migrations/` → both founders; `*.sql` com `SECURITY DEFINER` → both founders; 4-eyes obrigatório (`required_reviewers: 2`) |
| **On-call rotation técnica** | PagerDuty | Weekly rotation entre founders; escalation policy 15min |
| **Single Rekor anchor** | Existing Sigstore | Audit log entries assinadas K-service + anchored em Rekor; **NÃO triple-anchor ainda** (Phase 4) |

### Build sequence (10-12 semanas)

```
Mês 4 Sem 1-2 (DB foundation):
  Founder A: PostgreSQL RDS provision + RLS policies design + roles + grants (1 sem)
  Founder B: PgBouncer config + connection pool tests + load test (1 sem)
  Both:     ent ORM TenantInterceptor + tests cross-tenant leak attempt (1 sem)

Mês 4 Sem 3-4 (Backend API):
  Founder A: Backend Go service skeleton em ECS Fargate + IAM + ALB (1 sem)
  Founder B: API REST endpoints: orgs, repos, scans, findings, policies (1 sem)

Mês 5 Sem 1-2 (Frontend):
  Founder B: Frontend React skeleton + auth flow GitHub OAuth (1 sem)
  Founder A: Ingest endpoint `/v1/findings` + raw-evidence rejection test + ML-DSA-65 sign hookup (1 sem)

Mês 5 Sem 3 (K-service):
  Founder A: K-service signing sidecar broker (CIRCL-Go OR liboqs) (3 dias)
  Founder B: K-service rotation register publication endpoint (2 dias)

Mês 5 Sem 4 (Frontend complete):
  Founder B: Dashboard views: scan list, finding detail, policy editor, history chart
  Founder A: WebSocket live findings stream + frontend integration

Mês 6 Sem 1 (OPSEC + governance):
  Founder A: cryptoct_admin OPSEC runbook + EventBridge alerts wiring + CODEOWNERS
  Founder B: PagerDuty setup + on-call rotation + escalation

Mês 6 Sem 2 (Observability):
  Founder A: Sentry SaaS PII scrub + Datadog/Honeycomb tracing
  Founder B: Internal pen-test self-driven: cross-tenant leak attempts, RLS bypass, SQL injection

Mês 6 Sem 3-4 (Production cutover):
  Both: Canary deploy: 10% traffic → 50% → 100% over 1 sem
  Both: First 5 customers production onboarding técnico
```

### Dependências

- **Phase 2 estável e adopted** — wire format já em produção, customers usando GitHub App
- **AWS RDS PostgreSQL 16 disponível em sa-east-1** ✓
- **AWS KMS asymmetric key support** ✓
- **K-service sidecar implementation** — CIRCL-Go bridge ou liboqs broker pattern (ADR Phase 2 carregado adiante)

### Cross-cutting durante Phase 3

- **Threat model atualizado:** insider threat torna-se real. `cryptoct_admin` BYPASSRLS é blast-radius máximo — runbook + alertas + 4-eyes são gate de release Phase 3.
- **Wire format Phase 2 mantém-se v1:** Phase 3 não breaking-change o ingest; v2 só se Phase 4 mover para evidência tamper-evident requirement.
- **CI/CD pipeline:** GitHub Actions OIDC → ECS Fargate deploy via blue/green; rollback automático em health check fail.
- **Cross-tenant leak tests** são obrigatórios em CI — quebra de teste bloqueia merge em `main`.

### Demo-able state

- Customer acessa `cryptoct.com` → GitHub OAuth → vê dashboard com seus repos
- Histórico de 30+ dias de scans visível
- Comparativos cross-time (e.g., "RSA-2048 reduzido de 47→12 ocorrências nos últimos 30 dias")
- Policy editor visual + diff de policies entre versões
- WebSocket live findings stream durante scan em progresso

### Trigger para Phase 4

≥1 pedido técnico explícito por BYOK, **ou** por evidência tamper-evident verificável independentemente, **ou** por scanner sandboxing hardened. Ou seja: customer cuja arquitetura de segurança demanda complexidade adicional.

---

## Phase 4 prep window (Mês 8.5, ~2 semanas antes de Phase 4 começar)

Os itens que historicamente estavam em "Phase 0" mas que na verdade só são precondição da cerimônia Phase 4. Não bloqueiam Phase 1/2/3 — só precisam estar prontos antes do Mês 9 quando Phase 4 começa.

### Deliverables

- **4 ADRs P0** em `docs/adr/` (drafts de prosa, ~meio dia cada):
  - `0001-mofn-quorum-rationale.md` — por que M-of-N 2-of-3 para K-release
  - `0002-tls-root-quorum-rationale.md` — por que 3-of-5 para K-tls-root + rotation 5y
  - `0003-shamir-ram-opsec.md` — risco de RAM reconstruction para Shamir share
  - `0004-ceremony-trust-root.md` — trust root para cerimônia offline
- **`tails-pinning.yaml` co-assinado** por ≥2 of {founder, outside witness}; SHA-256 do Tails ISO co-assinado contra release oficial (evita "placeholder em prod" defect identificado no audit P0-1)
- **Outside witness identificado** com pubkey co-assinada em `tails-pinning.yaml`

### Build sequence

```
Mês 8.5 Sem 1:
  Founder A: ADRs 0001 + 0002 (1 dia cada)
  Founder B: ADRs 0003 + 0004 (1 dia cada)
  Both:     Outside witness onboarding + pubkey exchange (1 dia)

Mês 8.5 Sem 2:
  Both: tails-pinning.yaml co-assinatura ceremony; SHA-256 do Tails ISO verificado contra release oficial; commit assinado em main
```

### Dependências

- **Outside witness identificado** (1-2 semanas de busca/conversa pré-window se ainda não há candidato)
- **Plans 02/04 referenciam estes ADRs** — orphan references existem até este window. Aceito conscientemente.

### Trigger para Phase 4 (gate combinado)

Demanda técnica concreta por BYOK / triple-anchor / sandboxing **+** Phase 3 estável ≥3 meses **+** Phase 4 prep concluído (4 ADRs committed + tails-pinning co-assinado).

---

## Phase 4 — Enterprise hardening (Mês 9-12, trigger demanda Enterprise)

**Objetivo:** entregar release cerimônia offline (M-of-N quorum), BYOK customer-controlled keys, audit log triple-anchor, scanner sandboxing hardened, e Enterprise tier production-ready.

### Deliverables

| Componente | Stack/path | Conteúdo |
|---|---|---|
| **K-release ceremônia** | Tails OS pinned + 2× YubiHSM2 + outside witness | M-of-N 2-of-3; ISO co-assinada via `tails-pinning.yaml` (Phase 4 prep); dedicated ThinkPad isolado; `nvme format -s 1` pós-cerimônia |
| **BYOK adapter** | Go service; AWS KMS customer-controlled keys; customer pubkey export endpoint | Aceita customer KMS ARN; per-data-subject DEKs derived via HKDF-SHA-256; revoke customer KMS imediatamente bloqueia decrypt |
| **Audit log triple-anchor** | Sigstore Rekor + DigiCert TSA + e-Sec Brasil TSA | 3-of-3 quorum; verify-after-revoke procedure documentada |
| **Multi-region S3 sync** | sa-east-1 → us-east-2 via cross-region replication + S3 Object Lock Compliance mode | Multi-KMS scattered (4 KMS keys); deletion requires 4-eyes SCP `SCP-AUDIT-KMS-TAG-DENY` |
| **Scanner sandboxing** | gVisor (gvisor.dev) + nsjail para mvn sub-sandbox + zero-egress NetworkPolicy + seccomp profile | Defense-in-depth para scan executor — defesa contra hostile dep com exploit |
| **EKS + Falco** | Migration de ECS Fargate → EKS sa-east-1 + Falco community ruleset | Custom rules apenas se security eng adicional na equipe |
| **Self-hosted runner ephemeral** | Tier separado para signing-tier builds | Ephemeral GHA runner em isolated VPC; signing-tier nunca compartilha runner com build-tier |
| **Cofounder degraded-mode** | Time-locked single-signer | 7-day Rekor witness delay; ativada se outside witness indisponível por força maior |

### Build sequence (12-16 semanas)

```
Mês 9 Sem 1-2 (Ceremônia infra):
  Both:     Tails ISO build + co-assinatura ceremony (founders + outside witness)
  Founder A: YubiHSM2 procurement (2 hardware + 1 backup) + setup + key generation
  Founder B: ThinkPad dedicated + storage isolation + cold storage location

Mês 9 Sem 3-4 (BYOK):
  Founder A: BYOK adapter Go service + AWS KMS customer-controlled key acceptance flow (2 sem)
  Founder B: Per-data-subject DEK derivation via HKDF + key rotation flow (2 sem)

Mês 10 Sem 1-2 (Triple anchor):
  Founder A: Triple-anchor signer service (Rekor + DigiCert TSA + e-Sec Brasil) (2 sem)
  Founder B: Verify-after-revoke procedure + customer KMS revocation handling (1 sem)

Mês 10 Sem 3-4 (S3 hardening):
  Founder A: Multi-region S3 cross-region replication + Object Lock Compliance (1 sem)
  Founder B: Multi-KMS scattered + SCP-AUDIT-KMS-TAG-DENY + 4-eyes deletion gate (1 sem)
  Both:     Terraform locks + EventBridge drift alarm (1 sem)

Mês 11 Sem 1-2 (Scanner sandboxing):
  Both:     gVisor PoC com scan executor migration; performance regression test (1 sem)
  Both:     nsjail mvn sub-sandbox para Java JCE coalescer hostile dep defense (1 sem)
  Both:     NetworkPolicy zero-egress + seccomp profile tuning (1 sem)

Mês 11 Sem 3-4 (EKS migration):
  Both:     EKS cluster sa-east-1 provision + Falco install + custom-rule baseline (1 sem)
  Both:     ECS → EKS migration via canary (10% → 50% → 100%) (1 sem)

Mês 12 Sem 1-2 (Self-hosted signing runner):
  Founder A: Ephemeral GHA runner em isolated VPC + signing-tier separation
  Founder B: First K-release ceremônia executada para v1.0.0 cut

Mês 12 Sem 3-4 (Enterprise GA):
  Both:     First Enterprise customer technical onboarding: BYOK live + ceremônia evidência publicada
  Both:     End-to-end verification flow documentado: customer pode verify finding via Rekor OR DigiCert TSA OR e-Sec Brasil independentemente
```

### Dependências

- **Phase 3 production estável** ≥3 meses sem incidente P1+
- **Demanda técnica concreta** justificando complexidade adicional (BYOK, triple-anchor, ou sandboxing)
- **Phase 4 prep window concluído**: 4 ADRs committed + `tails-pinning.yaml` co-assinado + outside witness com pubkey conhecida
- **YubiHSM2 hardware procurement (3 unidades; lead time 4-8 sem)**
- **gVisor performance baseline aceitável** (PoC obrigatória antes de migration commit)

### Cross-cutting durante Phase 4

- **Cofounder coercion threat model explícito:** ADR adicional; outside witness pubkey fora da jurisdição BR.
- **BYOK threat model documentado em ADR:** quem é adversário do BYOK? Customer-side coercion vs operator-side coercion.
- **DR runbook:** AWS sa-east-1 single-region é SPOF até Phase 4; Phase 4 inclui multi-region S3 sync mas backend compute ainda single-region.
- **Release ceremônia replicável:** todo passo da cerimônia tem checklist + verifier independente. Cerimônia falhada → time-locked single-signer fallback acionado.

### Demo-able state

- K-release v1.0.0 cut com cerimônia executada; SHA-256 do release publicado em Rekor + DigiCert TSA + e-Sec Brasil TSA
- Customer Enterprise BYOK live: customer KMS ARN registrado; CryptoCT cifra DEKs com customer key; revoke do customer KMS imediatamente bloqueia decrypt de findings tenant
- Audit log triple-anchor: qualquer finding verify-able via Rekor OR DigiCert TSA OR e-Sec Brasil independentemente — falha de qualquer anchor único não compromete verificabilidade
- gVisor sandbox: scan de repo com payload hostil (CTF-style) é contido; egress zero confirmado

### Estado pós-Phase 4

Sem Phase 5 roadmapped. Decisões pós-Phase 4 (LATAM expansion, additional verticals, on-prem self-host) são trigger-based separadas e não cobertas neste roadmap.

---

## Cross-cutting de todas as fases

### Testing strategy (engenharia)

| Fase | Test types | Coverage target |
|---|---|---|
| Phase 1 | pytest unit + integration | ≥80% core |
| Phase 2 | Phase 1 + Go integration + end-to-end (clone-scan-PR-Check Run) + replay attack tests | ≥75% backend |
| Phase 3 | Phase 2 + cross-tenant leak tests + RLS bypass attempts + load test 100 concurrent tenants | ≥75% backend + ≥60% frontend |
| Phase 4 | Phase 3 + chaos engineering (region failover; KMS revoke; outside witness unavailable) + hostile-dep payload tests contra gVisor sandbox | ≥75% backend |

### Release sequence por fase

Cada phase tem uma **release cerimônia escalada**:

| Phase | Release type | Signer |
|---|---|---|
| 1 | PyPI release | Sigstore keyless (GHA OIDC → Fulcio → Rekor) |
| 2 | GitHub App version bump | Sigstore keyless (Lambda + Worker code) |
| 3 | SaaS deploy continuous | ECS blue/green; tag rastreável a Rekor |
| 4 prep | ADR commits + `tails-pinning.yaml` co-sig | signed commits founders + outside witness |
| 4 | K-release ceremônia | M-of-N 2-of-3 + outside witness + multi-anchor |

### Dependency upgrade policy

`pqcheck self-audit` é o gate. Toda dependency upgrade que move uma transitive crypto dep para PQC-incompatível bloqueia release até **remediation OR waiver assinado em ADR**. Histórico de waivers em `docs/security/waivers.md`. Esta policy aplica-se a todas as fases.

### Documentação técnica evolution

| Fase | Docs técnicos entregues |
|---|---|
| 1 | README + LICENSE + SECURITY.md + CONTRIBUTING + User guide + Policy schema reference + Examples folder + Self-audit + waiver workflow |
| 2 | Phase 1 + GitHub App setup guide + Wire format spec v1 + Workers/Lambda architecture docs |
| 3 | Phase 2 + Dashboard docs + API reference + OPSEC runbook + On-call runbook + RLS architecture |
| 4 prep | Phase 3 + 4 ADRs P0 (M-of-N quorum, TLS root quorum, Shamir RAM OPSEC, ceremony trust root) |
| 4 | Phase 4 prep + Ceremônia runbook + BYOK integration guide + Triple-anchor verification guide + gVisor sandbox tuning |

---

## Deploy pipeline evolution

```
Phase 1: tag v*.*.* → GHA → cibuildwheel → Sigstore                   → PyPI
Phase 2: tag v*.*.* → GHA → wrangler + sam-cli + GH App version       → Cloudflare Workers + AWS Lambda + GitHub Marketplace
Phase 3: main merge → GHA → ECS blue/green canary                     → cryptoct.com sa-east-1
Phase 4: tag v*.*.* → CERIMÔNIA OFFLINE → K-release sig multi-anchor  → S3 multi-region + Rekor + DigiCert TSA + e-Sec TSA
         + EKS GHA → canary → production EKS sa-east-1                → cryptoct.com com gVisor sandboxing
```

Cada deploy passo é versionável, auditável, e (em Phase 3+) tem rollback automático em health check fail.

---

## Sequência de dependências (grafo técnico simplificado)

```
Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 prep ──► Phase 4
PyPI         GH App      SaaS         4 ADRs        Enterprise
pqcheck      Wire fmt    RLS+K-svc    tails-pin     BYOK+ceremônia
CLI scan     Webhook     Dashboard    witness pub-  Triple-anchor
CBOM+SARIF   Lambda      Multi-tenant key exchange   gVisor+EKS
(Pre-flight Day 0: namespace + repo + LICENSE + branch protection — ~1h)

Trigger gates técnicos (NEVER skip):
  Day 0 → Phase 1 start: namespace PyPI reclamado + pyproject.toml válido + branch protection ativa
  1→2: 3+ CI integration requests OR 1 pilot conditional + Phase 1 estável
  2→3: ≥20 active customers + ≥3 requests por dashboard, OR financing event
  3→4 prep: Demanda técnica concreta por BYOK, triple-anchor OR scanner hardening (Mês 8.5)
  4 prep → 4: 4 ADRs committed + tails-pinning co-assinado + Phase 3 estável ≥3 meses
```

Cofounder-degraded-mode (sempre disponível): time-locked single-signer com 7-day Rekor witness delay; ativada se outside witness indisponível por força maior em qualquer fase ≥1.

---

## Referências

- Pitch executivo: [`00-local-first-pitch.md`](./00-local-first-pitch.md)
- Plano-mestre (inclui partes não-técnicas): [`01-master-plan.md`](./01-master-plan.md)
- Política PQC técnica: [`02-quantum-safe-crypto-policy.md`](./02-quantum-safe-crypto-policy.md)
- Phase 1 detalhado: [`03-phase1-pqcheck-cli.md`](./03-phase1-pqcheck-cli.md)
- Operações de segurança técnica: [`04-security-operations.md`](./04-security-operations.md)
- Auditoria adversarial: [`../../reason/260523-1030-plans-audit/converged-analysis.md`](../../reason/260523-1030-plans-audit/converged-analysis.md)
