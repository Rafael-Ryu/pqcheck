# CryptoCT — Planning Documents

> Conjunto canônico de planos para CryptoCT. Versão pós-cortes (2026-05-22) — overengineering removido, technical debt sources eliminados, hardening Enterprise (RLS multi-tenant, scanner gVisor, audit triple-anchor, BYOK 5-provider, EKS+Falco, K-release ceremônia Tails+YubiHSM) movido para ativação trigger-based na Phase 4.
>
> **Revisão 2026-05-23 (audit pós-reason-loop):** correções aplicadas — LGPD Art. 16 II→I (audit retention é cumprimento de obrigação legal); BCB Circ. 3.978/2020 → Res. 119/2021 + Circ. 4.001/2020 (norma vigente); Res. CMN 4.893/2021 + Res. BCB 85/2021 (atribuição correta); 4 ADRs criados Phase 0; Tails ISO hash via `tails-pinning.yaml` co-signed (não placeholder); Phase 1 timeline re-baseline 4-6 sem; budget 18m §6.1 expandido com founder comp + AWS baseline + equipment; lockfile parsers Phase 1 incluem pyproject.toml + uv.lock; supply-chain self-audit em CI obrigatório; CODEOWNERS migrations + 4-eyes; cryptoct_admin OPSEC runbook; Phase 3 ingest test rejeição evidence raw.

## Documentos

| # | Arquivo | Conteúdo |
|---|---|---|
| **00** | [**`00-local-first-pitch.md`**](./00-local-first-pitch.md) | **Front-door pitch:** o que CryptoCT é em 30s, MVP local-first que 2 fundadores entregam em 4-6 semanas, evolução Phase 0→4 com trigger falsificável por transição. Convergido via reason-loop adversarial 2026-05-23 (4 personas, 3 judges, 2 rounds). |
| 01 | [`01-master-plan.md`](./01-master-plan.md) | Plano-mestre: tese, posicionamento ANPD/Drex/BCB, arquitetura Phase 1-3 + design intent v1.0, stack, fases, cronograma trigger-based, compliance OpEx revisto, top risks (12 itens), GTM, contingência cofounder-only |
| 02 | [`02-quantum-safe-crypto-policy.md`](./02-quantum-safe-crypto-policy.md) | Política cripto vinculante: 8 algoritmos aprovados default, hierarquia de chaves (Phase 1-3 simples + Phase 4 ceremônia), aplicação por camada, cerimônia K-release deferida Phase 4, Transitive PQC Risk 5 itens, YAML schema |
| 03 | [`03-phase1-pqcheck-cli.md`](./03-phase1-pqcheck-cli.md) | Implementação Fase 1: CLI Python com policy engine, parsers, detectors, lockfile parsers, severity × confidence, Sigstore keyless signing, cibuildwheel matrix 3 platforms (Linux x86_64 + macOS x86_64/arm64) |
| 04 | [`04-security-operations.md`](./04-security-operations.md) | Operações de segurança: IR runbook fase-based, RLS Phase 3, scanner sandboxing Phase 3-4, BYOK Phase 4, KMS safeguards Phase 4, Tails ceremônia Phase 4, defensive squatting reduzido (4 registries + 3 domains), sub-processor disclosure por fase, bug bounty Phase 3, LGPD compliance ops mantido mês 1 |
| 05 | [`05-development-roadmap.md`](./05-development-roadmap.md) | Roadmap **de engenharia pura** Phase 0→4: build sequence semana-a-semana (Sem 0-6) e mês-a-mês (Mês 2-12), deploy milestones, dependências técnicas entre fases, demo-able state por fase, cross-cutting (test/CI/release/dependency policy/docs técnicos). **Sem partes legais, econômicas ou de compliance regulatória externa** — para isso ver 01 e 04. |

> **Reason-loop**: processo adversarial em que candidatos compostos por diferentes ângulos (technical cofounder, business cofounder, security skeptic, buyer CISO) são julgados por painel cego de 3 judges independentes. Convergência declarada quando todos os judges confirmam que o draft passa todas as personas sem contradições. Transcripts publicados em `autoresearch/` e `reason/` no repo.

## Ordem de leitura sugerida

1. **`00-local-first-pitch.md`** — apresentação executiva, 5 min de leitura
2. **`01-master-plan.md`** — entender produto, posicionamento, fases trigger-based, cronograma
3. **`05-development-roadmap.md`** — build sequence semana-a-semana e mês-a-mês, dependências, deploy milestones
4. **`03-phase1-pqcheck-cli.md`** — começar implementação do CLI imediatamente
5. **`02-quantum-safe-crypto-policy.md`** — entender política cripto + algoritmos aprovados
6. **`04-security-operations.md`** — entender quais controles ativam em qual fase

## Princípios não-negociáveis

1. **Vertical BR-first.** ANPD Art. 46 lidera; Drex segundo; BCB 4893 suporte (vendor-DD package, não compliance direta — vendor não é entidade supervisionada). Sem expansão LATAM antes de provar tese BR.
2. **PQC honesto.** Quantum-safe onde controlamos diretamente o protocolo. Onde dependemos de provider classical, declaramos em SECURITY.md (5 itens top-impact) com owner + mitigação.
3. **Plano como artefato executável.** Toda promessa de segurança vira código + integration test. Specs longas que envelhecem viram GitHub issues + ADRs.
4. **Customer trust by architecture, not promise.** BYOK arquitetura preservada como design intent v1.0 (Phase 4); ativada quando 1º Enterprise LOI demanda.
5. **Trigger-based provisioning.** Compliance avançada, ceremônia offline, sub-processadores caros, KMS providers múltiplos, payment processors duplos — ativados por customer-signal, não pré-emptivamente.
6. **SaaS antes de self-host.** Self-host apenas quando ANPD audit OR Enterprise SLA contracted explicitamente demanda.
7. **Defesa em profundidade contra nós mesmos.** Insider threat mitigado por arquitetura, ativado quando threat materializa (multi-tenant SaaS Phase 3+).

## Hard blockers por fase

**Phase 0-1 (mandatory pré-launch):**
- LTDA SP + DPO fractional (LGPD Art. 41 + Res. CD/ANPD 2/2022)
- DPIA + ROPA published (LGPD Art. 37; DPIA via Art. 38 quando ANPD-triggered OR high-risk)
- 4 registries claim (PyPI, Docker Hub, GitHub, npm) + 3 domains
- README + SECURITY.md + LICENSE
- Sigstore keyless release signing
- ADRs P0 criados em `docs/adr/`: 0001-mofn-quorum-rationale.md, 0002-tls-root-quorum-rationale.md, 0003-shamir-ram-opsec.md, 0004-ceremony-trust-root.md
- `pqcheck self-audit` em CI release pipeline obrigatório (supply-chain transitive deps gate)
- `tails-pinning.yaml` co-signed by ≥2 of {founder, outside witness} (Phase 4 pre-trigger gate)

**Phase 3 ativação (trigger: ARR > R$ 800k run-rate OR Series Seed signed):**
- PostgreSQL RLS multi-tenant
- ECS Fargate + AWS GuardDuty + CloudTrail
- Sentry SaaS + Datadog/Honeycomb DPA
- ML-DSA-65 sidecar (K-service, server-side via broker pattern) — Phase 3. K-release ceremony (offline-courier, YubiHSM2, Tails) — Phase 4
- PagerDuty + on-call rotation
- Vanta/Drata signup
- Annual pen-test externo
- Bug bounty Intigriti

**Phase 4 ativação (trigger: 1º Enterprise LOI assinado, financiado pelo deal):**
- K-release ceremônia (Tails + 2×YubiHSM2 + outside witness + cartório SP)
- BYOK adapter AWS KMS + customer pubkey export
- Audit log triple anchor 3-of-3 (Rekor + 2× RFC 3161 TSA)
- Multi-region S3 sync per-insert + S3 Object Lock Compliance multi-KMS scattered
- Scanner pod gVisor + nsjail mvn sub-sandbox + zero-egress NetworkPolicy + seccomp
- EKS + Falco community ruleset (custom rules apenas se security eng hired)
- Self-hosted runner ephemeral + signing-tier isolated
- Tails ISO pinning + dedicated hardware + cofre bancário
- SOC 2 Type II observation window inicia
- ISO 27001 stage 1-2

## Resumo executivo dos cortes aplicados

| Métrica | Original | Final |
|---|---|---|
| Phase 0 eng-days | 47-77 | 5-10 |
| Phase 0 gov-days | 8 | 2 |
| Sem launch → HN | 8-12 (após P0 closure) | 2-4 |
| Compliance OpEx 18m (sem Phase 4) | R$ 1.3-2.3M | R$ 525-940k |
| Algoritmos aprovados default | ~25 | 8 |
| Sub-processadores Phase 1-2 | 12 | 5 |
| PQC debt items tracked | 22 | 5 |
| Risk register | R1-R30 + 60 vectors | 12 top risks |
| Wheel platforms v0.1 | 5 | 3 |
| Pricing tiers launch | G0-G3 × 2 currencies | 1 (free CLI + 1 paid) |
| Audit anchors Phase 3 | Triple 3-of-3 | Single Rekor |
| Defensive registrations | 12 registries + 8 domains | 4 registries + 3 domains |
| K-release ceremony em v0.1 | Tails+YubiHSM+cartório+outside witness | Sigstore keyless (cerimônia → Phase 4) |

## Próximos passos imediatos

1. **Sem 0-1:** LTDA SP + DPO fractional + registries core + repos + README/SECURITY.md/LICENSE
2. **Sem 2:** v0.0.1 dev preview (Sigstore keyless, Linux x86_64 wheel)
3. **Sem 3:** DPIA + ROPA publicados + v0.1.x preview (LGPD Art. 8 §5 + Art. 6 VI exigem privacy notice ANTES da coleta)
4. **Sem 4:** HN Show HN launch (apenas após DPIA publicado)
5. **Mês 2:** Phase 2 GitHub App (Cloudflare Workers + AWS Lambda)
6. **Mês 4-6:** Phase 3 SaaS dashboard ativação se ARR > R$ 800k run-rate
7. **Mês 9-12:** Phase 4 ativação trigger-based (apenas se 1º Enterprise LOI assinado)
