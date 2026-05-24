# CryptoCT — Local-First Pitch

> Front-door doc do projeto. Conjunto canônico de planos em `01-04.md`.
> Esta v0.1 do pitch foi convergida via reason-loop adversarial (4 personas, 3 judges) em 2026-05-23. Transcripts em [`../../autoresearch/reason-260523-1145/`](../../autoresearch/reason-260523-1145/).

---

## 1. O que CryptoCT é, em 30 segundos

`pqcheck` é uma ferramenta CLI Python (free, open-source, Apache-2.0) que escaneia um repositório de código, identifica todos os algoritmos criptográficos em uso — incluindo dependências transitivas — e gera um **CBOM padrão CycloneDX 1.6 + relatório SARIF** validado contra uma política PQC versionável em YAML.

```bash
$ pqcheck scan ./example-fintech --policy=br-bcb-conservative.yaml
✗ example-bank/src/auth/jwt.py:42    - RSA-2048 (BANNED: Shor-vulnerável)
✗ example-bank/go.mod                - crypto/ecdsa@v1.21.0 (BANNED transitively)
⚠ example-bank/src/tls/server.py:18   - X25519 sem hibrido ML-KEM (WARNING)
✓ example-bank/src/storage/aead.py    - AES-256-GCM (APPROVED)

CBOM:   ./cbom.cdx.json  (CycloneDX 1.6, 47 components, 8 cryptographic findings)
SARIF:  ./pqcheck.sarif   (importável em GitHub Code Scanning)
Policy: br-bcb-conservative.yaml (8 allowed, 3 banned, 2 warning)
```

> *Output ilustrativo; demo real em `examples/`.*

**O que muda para o cliente:** o levantamento criptográfico que hoje é planilha de 2-4 semanas por auditoria vira `pqcheck scan` em segundos, **com a mesma evidência citável que o auditor BCB ou ANPD aceita** (CBOM CycloneDX 1.6 + SARIF 2.1.0, ambos padrões CISA/OWASP).

---

## 2. Quem paga por isto hoje (em horas-homem internas)

| Persona | Dor concreta hoje | O que `pqcheck` substitui |
|---|---|---|
| **CISO de banco BCB Nível 1-3 e fintech digital** (Inter, C6, Original, Nubank-tier) | Auditoria interna anual + auditoria BCB cíclica. Inventário cripto montado puxando dependency tree à mão em planilha. 2-4 semanas de eng-time/auditoria. Não detecta transitive. | `pqcheck scan` + CBOM + SARIF anexado ao laudo |
| **Compliance Officer de fintech regulada** | Vendor due-diligence cripto-anexo para Visa/Master/correspondente bancário. Hoje pede checklist ao eng; resposta em semanas, manual, PDF assinado a mão. | CBOM versionável + policy YAML anexada como evidência de governança |
| **Engenharia de plataforma em entidade Drex-piloto** | BCB mandou roadmap PQC. Hoje a ferramenta é leitura manual de SBOM ou greps custom. | `pqcheck self-audit` + policy `br-drex-piloto.yaml` em CI |

Cada uma destas três pessoas paga por isto **agora**, em horas-homem internas — só não tem linha em DRE.

---

## 3. O problema, sem hipérbole

Três forças simultâneas obrigam **entidades reguladas BR específicas** a inventariar e migrar criptografia nos próximos 24-36 meses:

1. **NIST finalizou FIPS 203/204/205** (ML-KEM, ML-DSA, SLH-DSA) em ago/2024. RSA e ECDSA entram em sunset; CISA, NSA-CNSA-2.0 e BSI já publicaram cronogramas até 2030-2035.
2. **Regulação BR já trata crypto-risk como auditável.** Res. CMN 4.893/2021 + Res. BCB 85/2021 exigem inventário criptográfico e gestão de risco cibernético. LGPD Art. 46 + ANPD orientação 04/2024 enquadram algoritmo obsoleto como falha técnica. Drex (CBDC BCB) tem requisitos PQC explícitos para participantes.
3. **Concorrentes existentes não fecham o ciclo BR-specific.** `cbomkit` (IBM) gera CBOM com mapeamento NIST/US, sem frame regulatório BR. `cyclonedx-python` gera SBOM mas não interpreta semântica criptográfica. `cryptography-inventory` (NCSC pattern) é parser, não validator. Snyk, GitHub Advanced Security e Checkmarx não tratam algoritmo crypto como classe de finding.

**Audience v0.1:** bancos sob supervisão BCB Nível 1-3, fintechs Pix-direct, participantes Drex, e fornecedores destes (vendor-DD anexo cripto). Pequenos POPs e credit-union-tier ficam fora — têm anos de runway.

**Defensibilidade específica vs ferramentas existentes:**
- **(a) Frame regulatório BR**, não US/NIST. Default policies já mapeadas a Res. BCB 85, LGPD Art. 46 e roadmap Drex.
- **(b) Workflow de governança traceable.** Policy YAML + CODEOWNERS-gated + ADR-traceable waiver flow. Não é diferencial de feature isolada — é diferencial de processo auditável.
- **(c) Default policies tuned para fintech BR** (`br-bcb-conservative.yaml`, `br-drex-piloto.yaml`, `br-vendor-dd.yaml`) — não é tooling vazio com policy DIY.

---

## 4. MVP local-first: o que 2 fundadores entregam em 4-6 semanas

**Premissa:** v0.1 inteira roda em laptop. Sem AWS, sem KMS, sem SaaS, sem GitHub App, sem cerimônia offline.

**Modelo de negócio:** CLI grátis para sempre. Receita inicia em Phase 3 com SaaS dashboard pricing (1 tier pago + free CLI). Nada cobrado em v0.1.

### Escopo de v0.1

| Componente | Por que está em v0.1 |
|---|---|
| `pqcheck` CLI Python (`pip install pqcheck`) | Unidade mínima que produz valor sem servidor |
| Detector Python (AST stdlib) | Maior base BR-fintech backend |
| Detector Go (tree-sitter) | Backends Pix, core fintech |
| Detector Java (tree-sitter + JCE coalescer) | Core bancário legado |
| 8 lockfile parsers — `pyproject.toml`, `uv.lock`, `go.mod`, `pom.xml`, `package-lock.json`, `Gemfile.lock`, `Cargo.lock`, `composer.lock` | Cobertura transitive deps |
| Policy schema `pqcheck-policy-v1.yaml` + 3 default policies (`br-bcb-conservative`, `br-drex-piloto`, `br-vendor-dd`) | Política como código auditável; CODEOWNERS-gated |
| Output CycloneDX 1.6 CBOM | Padrão CISA/OWASP, integra fluxo SBOM existente |
| Output SARIF 2.1.0 | Importável em GitHub Code Scanning, Sonar |
| `pqcheck self-audit` CI gate | Se falha, release bloqueada até remediation OR waiver assinado em ADR; histórico em `docs/security/waivers.md` |
| Precision target ≥0.85 em corpus 10-repo benchmark BR-fintech | Se eval falha, ship `--strict` opt-in apenas (modo default permissivo, opt-in strict) |
| Sigstore keyless release signing | Free, sem hardware, sem cerimônia |
| cibuildwheel matrix Linux x86_64 + macOS x86_64/arm64 | Cobre dev-stations BR fintech típicas em v0.1 |
| README EN/PT + SECURITY.md + LICENSE | EN para PyPI/GitHub global; PT para BR-context |
| DPIA + ROPA publicados | LGPD Art. 8 §5 + Art. 6 VI; DPO fractional draft Sem 0-3 paralelo |
| 4 ADRs em `docs/adr/` (M-of-N quorum, TLS root quorum, Shamir RAM OPSEC, ceremony trust root) | Trust-root rationale documentado antes de v0.1 |

### Esforço — defesa do "4-6 semanas com 2 pessoas"

| Item | eng-days |
|---|---|
| 3 detectors (Python AST, Go tree-sitter, Java tree-sitter + JCE coalescer) | ~24 |
| 8 lockfile parsers | ~10 |
| Policy engine YAML + schema + 3 default policies BR-tuned | ~5 |
| CycloneDX 1.6 + SARIF 2.1.0 output | ~4 |
| Sigstore GitHub Action + cibuildwheel matrix | ~3 |
| `self-audit` CI gate + waiver workflow | ~2 |
| 10-repo precision benchmark + `--strict` fallback | ~5 |
| README EN/PT + SECURITY.md + 4 ADRs | ~6 |
| DPIA + ROPA via DPO fractional (paralelo, founder-time ~0.3 FTE) | (cobrado em DPO-horas + legal review) |

**Total: 50-65 eng-days × 2 fundadores FT (5 d/sem) = 5-7 semanas brutas.** Compliance ops puxa 0.3 FTE de um founder. **Realista 4-6 semanas.**

### Budget Phase 0+1 detalhado

| Item | Faixa |
|---|---|
| Founder comp (R$ 12-18k/m × 2 founders × 6 sem) | R$ 36-54k |
| LTDA SP setup + contabilidade 6 m | R$ 6-12k |
| DPO fractional (R$ 4-7k/m × 1-3 m) | R$ 4-21k |
| Legal review DPIA/ROPA + revisão de termos | R$ 8-15k |
| Domínios 3× (PyPI/Docker Hub/npm/GitHub registries são grátis) | R$ 0.5-1k |
| Equipment (laptops existentes, dev tools OSS) | R$ 0 |
| AWS baseline v0.1 (zero — roda local) | R$ 0 |
| **Total Phase 0+1** | **R$ 55-103k** |

Budget completo 18m e survival math (incluindo founder comp continuado + AWS baseline Phase 3 + equipment Phase 4) em `01-master-plan.md §6.1`: **R$ 1.9-2.85M** Phase 0-3 sem trigger Phase 4 (revisão pós-audit-loop¹ 2026-05-22).

> ¹ *reason-loop = processo adversarial em que candidatos compostos por diferentes ângulos são julgados por painel cego. Convergência declarada por unanimidade do painel. Ver transcripts em `reason/` no repo.*

### Demo de 30 segundos (cofundador apresentando em meetup)

> *"Em 24 meses, bancos BCB Nível 1-3, fintechs Pix-direct e participantes Drex vão precisar provar quais algoritmos crypto rodam no código deles — porque Res. BCB 85 e Drex já exigem, e RSA/ECDSA entram em sunset NIST. Hoje fazem em planilha, 2-4 semanas/auditoria. `pqcheck` escaneia, produz CBOM CycloneDX 1.6 padrão, valida contra política PQC versionável, gera SARIF que o auditor importa direto no GitHub Code Scanning. Free, open source, roda em laptop. PyPI em 4-6 semanas."*

---

## 5. O que CryptoCT NÃO promete em v0.1 (honesto)

Cada limite explícito hoje evita virar passivo amanhã.

- ❌ **Kotlin Android / Swift iOS:** v0.1 não escaneia mobile. Chega em v0.2 puxado por primeira fintech pagante que demande.
- ❌ **Rust / C / C++:** mesmo critério — pull-based.
- ❌ **Multi-tenant SaaS:** roda só local. CryptoCT-empresa não é controlador LGPD além de email opt-in newsletter.
- ❌ **Cloud KMS / BYOK:** chaves nossas são apenas as de assinatura PyPI (Sigstore keyless).
- ❌ **Cerimônia offline (Tails + YubiHSM2 + cartório):** Phase 4, trigger 1º Enterprise LOI.
- ❌ **GitHub App nativa:** roda no CI do cliente. App = Phase 2.
- ❌ **Dashboard SaaS:** findings em arquivo local + CI. UI = Phase 3.
- ❌ **Drex/CBDC compliance direta:** discutimos posicionamento; não atendemos. Drex exige contrato BCB direto.
- ❌ **Suporte 24/7:** best-effort GitHub Issues + email. PagerDuty = Phase 3.
- ❌ **SOC 2 / ISO 27001:** Phase 4.
- ❌ **Audit log triple-anchor:** v0.1 não tem audit log persistido (não há servidor). Triple-anchor = Phase 4.
- ❌ **Garantia de 0 false positives:** target precision ≥0.85 v0.1. Se eval falha, ship `--strict` opt-in apenas.

Documentação canônica em `SECURITY.md` "Transitive PQC Risk" — 5 itens top-impact com owner + mitigação.

---

## 6. Evolução: cada fase responde a uma mudança falsificável no problema

**Princípio:** trigger-based, não calendar-based. Cronograma por trimestre é hostage à execução; trigger é hostage ao problema.

> **Nota:** Phase 0 foi removida como fase separada. Pré-requisitos triviais (namespace PyPI + repo + LICENSE + branch protection) se resolvem em ~1h no Day 0 de Phase 1. Itens trust-root para Phase 4 (4 ADRs + `tails-pinning.yaml`) movem para "Phase 4 prep window" no Mês 8.5. Compliance/legal (LTDA, DPO, DPIA, ROPA) corre em track paralelo, não-bloqueante para Phase 1 (que não coleta dados) e necessário antes de Phase 2 (que recebe webhook payloads). Ver `05-development-roadmap.md`.

| Transição | Trigger primário (falsificável e contável) | O que mudou no problema | O que ativa na arquitetura |
|---|---|---|---|
| **Day 0 → Phase 1** | Namespace PyPI reclamado + repo GitHub + `pyproject.toml` válido + branch protection ativa (~1h) | "Vamos começar a escrever código" | Repo público, pre-flight setup mínimo |
| **1 → 2** | **3+ inbound requests para CI-integrated scan que CLI sozinha não satisfaz**, OU 1 pilot pago conditional em CI integration | "Quero auto-scan em PR, sem rodar local em cada PR" | Cloudflare Workers webhook receive; AWS Lambda sa-east-1 scan exec; wire format CLI→ingest (somente findings redigidos `hash_prefix`/`ast_node_kind`/`line_range`, **nunca evidence raw**); DPA + LGPD addendum; sub-processor disclosure (Cloudflare + AWS + GitHub); ML-DSA-65 nonce-windowed sig em payload (compensating control EXC-001 GitHub App JWT RS256 upstream limitation) |
| **2 → 3** | ARR > R$ 800k run-rate **ou** Series Seed assinada | "Múltiplos clientes pagantes querem histórico, dashboard, comparativos cross-time" | PostgreSQL RLS multi-tenant (`cryptoct_app` role + `SET LOCAL tenant_id` per request); `cryptoct_admin` BYPASSRLS com OPSEC runbook (vault, MFA hardware, 4-eyes, EventBridge alert SET ROLE); CODEOWNERS `migrations/` + 4-eyes obrigatório em `SECURITY DEFINER`; ECS Fargate + GuardDuty + CloudTrail + Sentry SaaS; ML-DSA-65 K-service sidecar (broker pattern, server-side audit sig); PagerDuty + on-call rotation; pen-test externo anual; Vanta/Drata + SOC 2 Type I observation; bug bounty Intigriti. **Audit log retention legal basis: LGPD Art. 16 I** (cumprimento obrigação legal/regulatória — *não* Art. 16 II). |
| **3 → 4** | 1º Enterprise LOI assinada, financiada pelo deal | "Enterprise quer soberania de chave e evidência tamper-evident para litígio; adversário inclui ordem judicial BR contra operador ou customer" | K-release ceremônia (Tails ISO pinned + 2× YubiHSM2 + outside witness + cartório SP); **BYOK adapter AWS KMS + customer pubkey export — Cloud Act hedge: a partir desta fase CryptoCT armazena dados de tenants sob jurisdição AWS sa-east-1, sujeitos a Cloud Act se US gov ordenar contra Amazon Inc.; BYOK move vetor para customer-controlled key**; audit log triple-anchor 3-of-3 (Rekor + DigiCert TSA + e-Sec Brasil); multi-region S3 sync + S3 Object Lock Compliance multi-KMS; scanner pod gVisor + nsjail mvn sub-sandbox + zero-egress NetworkPolicy + seccomp; EKS + Falco community ruleset; self-hosted runner ephemeral + signing-tier isolated; SOC 2 Type II window; ISO 27001 stage 1-2; **4-eyes SCP em deleção KMS — impede operador único, ou autoridade ordenando contra operador único, apagar chaves audit-tier; deleção exige 2 administradores em janelas separadas** |

**Cofounder degraded-mode contingência (sempre disponível):** time-locked single-signer com 7-day Rekor witness delay. Ativada se outside witness indisponível por força maior.

**Estado-estável honesto:** se cliente pagante não aparecer, Phase 3 não acontece. Plano: cofundador-only contingência em R$ 800k-1.2M ARR floor, time-locked degraded-mode.

---

## 7. Cronograma resumido

| Período | Ativo |
|---|---|
| Sem 0-1 | LTDA SP + DPO fractional + DPIA drafting (paralelo, DPO-side) + 4 registries + 3 domínios + repos + 4 ADRs |
| Sem 2 | v0.0.1 dev preview PyPI (Linux x86_64 wheel, Sigstore-signed) |
| Sem 3 | DPIA + ROPA publicados em cryptoct.com/privacy; v0.1.x preview |
| Sem 4-6 | Show HN launch + bug bash + v0.1.0 stable |
| Mês 2-3 | Phase 2 decision (apenas se 3+ inbound CI requests ou 1 pilot pago condicional) |
| Mês 4-6 | Phase 3 decision (apenas se ARR > R$ 800k ou seed) |
| Mês 9-12 | Phase 4 decision (apenas se 1º Enterprise LOI) |

---

## 8. Próximos passos imediatos

1. **Esta semana:** LTDA SP + DPO fractional + claim 4 registries + claim 3 domínios
2. **Sem 2:** v0.0.1 dev preview PyPI (Linux x86_64 wheel, Sigstore-signed)
3. **Sem 3:** DPIA + ROPA publicados; 4 ADRs commit em `docs/adr/`
4. **Sem 4-6:** Show HN launch — *"PQC compliance scanner BR-first, OSS"*

---

## 9. Referências

- Plano-mestre detalhado: [`01-master-plan.md`](./01-master-plan.md)
- Política PQC vinculante: [`02-quantum-safe-crypto-policy.md`](./02-quantum-safe-crypto-policy.md)
- Implementação Phase 1: [`03-phase1-pqcheck-cli.md`](./03-phase1-pqcheck-cli.md)
- Operações de segurança fase-based: [`04-security-operations.md`](./04-security-operations.md)
- Auditoria adversarial: [`../../reason/260523-1030-plans-audit/converged-analysis.md`](../../reason/260523-1030-plans-audit/converged-analysis.md)
- Reason-loop deste pitch: [`../../autoresearch/reason-260523-1145/`](../../autoresearch/reason-260523-1145/)

---

**Local-first. Roda em laptop, hoje. PyPI em 4-6 semanas. Tudo depois disso é trigger-based.**
