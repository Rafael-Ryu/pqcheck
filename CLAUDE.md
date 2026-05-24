# CLAUDE.md — pqcheck development context

Orientação para qualquer sessão Claude trabalhando neste repo. Ordem de leitura: este arquivo → `.context/plans/README.md` → plano específico conforme necessário.

## Projeto

`pqcheck` é o CLI da Phase 1 do **CryptoCT** — scanner de risco criptográfico pós-quântico para código-fonte e grafos de dependência, com vertical financeira brasileira (ANPD LGPD Art. 46, Drex / Pix, BCB Res. 4.893/2021).

`pqcheck` é working name; pode mudar antes do release público. Repo está privado em `Rafael-Ryu/pqcheck`.

## Onde o contexto vive

Toda a planning context está em `.context/plans/` (gitignored — local-only, não vai pro repo):

| Arquivo | Conteúdo | Criticidade para dev |
|---|---|---|
| `README.md` | Índice + ordem de leitura | **Alta** (orientação) |
| `00-local-first-pitch.md` | Pitch 30s + product framing | Média (contexto) |
| `01-master-plan.md` | Tese, posicionamento, arquitetura, risks, GTM | Média (high-level) |
| `02-quantum-safe-crypto-policy.md` | **8 algoritmos aprovados, hierarquia de chaves, política vinculante** | **CRÍTICA** — é a spec que pqcheck enforça |
| `03-phase1-pqcheck-cli.md` | **Implementação Phase 1: CLI, detectors, parsers, severity × confidence, file structure, tasks 1-12** | **CRÍTICA** — é o que construir |
| `04-security-operations.md` | Security ops, IR runbook, self-audit | Baixa-média (relevante para SECURITY.md futuro e self-audit gate) |
| `05-development-roadmap.md` | **Build sequence Sem 0-4, dependências, deploy milestones** | **CRÍTICA** — é a ordem |

Para dev imediato, leitura mínima: `03` (o que construir) + `05` (em qual ordem). `02` é referência sempre-aberta durante implementação de detectors/policy engine.

## Convenções de código

- **Python 3.12+** (pyproject.toml enforça `requires-python = ">=3.12"`)
- **uv** para deps + venv + builds: `uv sync --all-extras`, `uv run pytest`, `uv build`
- **ruff** lint (config em pyproject.toml — selects E/F/W/I/UP/B/SIM/RUF/S/PL/PTH)
- **mypy strict** type-check (`uv run mypy`)
- **pytest** com `--cov-fail-under=85`
- **hatchling** build backend; layout `src/`
- Comentários **só quando o WHY não é óbvio do código**. Não explicar WHAT (nomes já fazem isso). Não comentar sobre tasks/PRs/issues atuais — isso vive em commit messages e PR descriptions, não no código.
- **Não criar** CHANGELOG/SECURITY/CONTRIBUTING durante dev privado — premature. Adicionar quando for público.

### Deviation do plano: pins de deps

O `pyproject.toml` usa `>=X,<NEXT-MAJOR` ranges em vez de `MAJOR.MINOR.*` strict (como o plano original sugeria). Motivo: `sigstore==3.5.*` só tem pre-releases no PyPI; `pydantic==2.9.*` conflita com sigstore 4.x. Reprodutibilidade exata vem via `uv.lock` (já committed). Discipline strict aplica na lock layer, não na abstract layer.

## Princípios não-negociáveis (não re-derivar)

Os planos foram convergidos via adversarial reason-loop (3 judges blind panel, 2 rounds). **Não re-discutir essas decisões em sessão de implementação** — se realmente parecerem erradas, sinalizar ao usuário antes de mudar.

1. **Vertical BR-first.** ANPD lidera; Drex segundo; BCB suporte. Sem expansão LATAM antes da tese BR provada.
2. **PQC honesto.** Quantum-safe onde controlamos o protocolo; classical-deps declarados em SECURITY.md (Transitive PQC Risk 5 items) com owner + mitigação.
3. **Plano como artefato executável.** Toda promessa de segurança vira código + integration test. Specs longas que envelhecem viram issues + ADRs em `docs/adr/`.
4. **Customer trust by architecture, not promise.** BYOK preservado como design intent v1.0 (Phase 4); ativado quando 1º Enterprise LOI demanda.
5. **Trigger-based provisioning.** Compliance avançada, ceremônia offline, multi-KMS, etc. ativados por customer-signal, não pré-emptivamente.
6. **SaaS antes de self-host.** Self-host apenas se ANPD audit OR Enterprise SLA contratado.
7. **Defesa em profundidade contra nós mesmos.** Insider threat mitigado por arquitetura, ativado quando threat materializa (multi-tenant SaaS Phase 3+).

## Estado atual (2026-05-23)

✅ **Pre-flight concluído.** Scaffold criado, push em `Rafael-Ryu/pqcheck` private. Verificação local toda verde:
- `uv sync --all-extras` → 27 packages resolvidos
- `uv build` → sdist + wheel OK
- `twine check dist/*` → PASSED
- `uv run pytest` → 2 passed
- `uv run ruff check .` → clean
- `uv run mypy --strict` → no issues

### Próximo: Sem 0 dia 1

Per `.context/plans/05-development-roadmap.md` §"Build sequence":

```
Sem 0 (Day 0 manhã: pre-flight setup ~1h) ← CONCLUÍDO
Sem 0 resto: começa código imediatamente
  Founder A: detector Python AST (3 dias) + lockfile parsers pyproject/uv/pom (2 dias)
  Founder B: policy schema + YAML loader (2 dias) + 3 default policies (2 dias)
  Both:      pyproject.toml completo + GitHub Actions skeleton + cibuildwheel config (1 dia, paralelo)
```

Detalhe granular dos componentes em `.context/plans/03-phase1-pqcheck-cli.md` Tasks 1-12 (linhas ~133+) com domain models, severity × confidence matrix, file layout `src/pqcheck/`, etc.

## O que foi deliberadamente NÃO feito no pre-flight

Para evitar overengineering e committment caro pré-validação:

- ❌ Não criada GitHub org `cryptoct` (decisão: solo private dev primeiro)
- ❌ Não reclamados PyPI / Docker Hub / npm namespaces (defer até pre-launch Sem 3-4)
- ❌ Não comprados domínios `cryptoct.com` / `.com.br` / `.dev`
- ❌ Não comprado 2FA hardware (YubiKey) obrigatório
- ❌ Não criado CI workflow (`.github/workflows/`) — Sem 0 dia 4 quando houver código real
- ❌ Não criados SECURITY.md / CONTRIBUTING.md / CHANGELOG.md no repo (defer até público)

Quando for hora de público (Sem 3-4), revisitar `.context/plans/README.md` §"Hard blockers por fase" + `.context/plans/05-development-roadmap.md` §"Pre-flight setup".

## Working agreements com o usuário (Rafael Ryu)

- Responder em português (a menos que o usuário mude para inglês).
- Brainstorming/exploratory questions: 2-3 sentenças com recomendação + tradeoff, não implementar até ele aprovar.
- Para implementation tasks: usar a skill `superpowers:executing-plans` quando há um plano escrito; senão `superpowers:brainstorming` antes de code criativo.
- TaskCreate/TaskUpdate para rastrear progresso quando ≥3 passos distintos.
- Commits: apenas quando ele pedir explicitamente. Mensagens em inglês (convenção open-source futura), corpo focado no "why" não no "what".
- Não inventar URLs/recursos. Não criar docs (`.md` extras) sem ele pedir.
