# CryptoCT — Security Operations

> Documento canônico pós-cortes. Phase 1-3 = setup mínimo. Hardening Enterprise (RLS, scanner gVisor, audit triple-anchor, BYOK, EKS+Falco, Tails ceremônia) é Phase 4 trigger-based.

---

## 1. Incident Response (IR)

### 1.1 Phase 1-2 (current)

- Email + Signal contact em SECURITY.md
- Resposta inicial: 24h best effort founders
- Sem PagerDuty (CLI sem runtime production → sem pages possíveis)
- 3 dias úteis ANPD Res. CD/ANPD 15/2024 + LGPD Art. 48 §1 (notificação em prazo razoável; "3 dias úteis" reflete orientação ANPD pós-Comunicado 2/2023, não literal no Art. 9 da Res. 15/2024) — comunicação via email + Signal

### 1.2 Phase 3 ativação (SaaS launch)

- PagerDuty (R$ 2-5k/mês) + on-call rotation founders (1-week)
- Alert sources: AlertManager (Prometheus) + Sentry SaaS + Datadog + WAF (Cloudflare) + status page errors
- **Severity ladder + SLA:**

| Severity | Trigger | Response | Customer notification |
|---|---|---|---|
| P0 | Customer data exposed; RCE; bug bounty Critical | Pager 24/7; ack 15min; mitigation 4h | 3 dias úteis ANPD Res. 15/2024 |
| P1 | Production service down >5min; bug bounty High | Pager 24/7; ack 30min; mitigation 8h | 24h if customer-visible |
| P2 | Degraded service; failed precision corpus | Business hours; ack 4h; mitigation 24h | None unless escalates |
| P3 | Minor bug; documentation drift | Business hours; weekly triage | None |

### 1.3 Phase 4 ativação (1º Enterprise LOI)

Adiciona:
- Key compromise scenarios (K-release, K-image, K-audit-tenant) com runbook detalhado
- Scanner pod escape detection (Falco)
- Audit log anchoring failure handling (Rekor down, TSA timeout)
- Quarterly tabletop exercises (rotating: K-release compromise, scanner pod escape, BYOK customer KMS revoke, ANPD inquiry)
- Threat intel subscriptions (Feedly, GreyNoise Community, OTX, NIST NVD, BR-specific ANPD/BCB feeds, Sigstore/CIRCL upstream)

### 1.4 Post-mortem cadence

- **Mandatory:** P0 + P1 incidents
- **Template:** `docs/incidents/POSTMORTEM_TEMPLATE.md`
- **Cadence:** within 7d of resolution; published to customers via dashboard (Phase 3+)

---

## 2. Observability policy

### 2.1 Phase 1-2 setup

- Cloudflare Workers logs (24h retention, PII scrub em path params + header values)
- GitHub Actions logs (default)
- Sem self-hosted observability stack

### 2.2 Phase 3 ativação (SaaS launch)

**Sentry SaaS** com PII scrub:
```javascript
Sentry.init({
    dsn: process.env.SENTRY_DSN,
    sendDefaultPii: false,
    integrations: [
        Sentry.replayIntegration({ enabled: false }),  // EXPLICITLY DISABLED
    ],
    beforeSend(event) {
        if (event.request?.data) delete event.request.data;
        if (event.contexts?.payload) delete event.contexts.payload;
        if (event.extra?.source_code) delete event.extra.source_code;
        event.exception?.values?.forEach(ex => {
            ex.stacktrace?.frames?.forEach(frame => {
                delete frame.vars;
                delete frame.context_line;
                delete frame.pre_context;
                delete frame.post_context;
            });
        });
        return event;
    },
});
```

**Datadog/Honeycomb** com DPA assinada para metrics + traces.

**Backend slog scrub middleware (Go):**
```go
// internal/logging/scrubbed_handler.go
var bannedAttrNames = map[string]bool{
    "content": true, "source": true, "code": true, "expr": true,
    "ast": true, "raw": true, "body": true, "payload": true,
    "stack": true, "traceback": true, "exception_value": true,
}

var allowedAttrNames = map[string]bool{
    "tenant_id": true, "request_id": true, "trace_id": true, "span_id": true,
    "method": true, "status": true, "duration_ms": true, "file_path_hash": true,
    "algorithm": true, "severity": true, "policy_id": true, "version": true,
    "operation": true, "error_code": true,
}
```

### 2.3 Phase 4 ativação (se ANPD audit demanda residência)

- Self-host Loki + Tempo + Grafana sa-east-1
- Promtail replace stages (long-token, JWT, email, CPF/CNPJ redaction)
- Tempo + Loki tenant isolation via `X-Scope-OrgID` header
- GlitchTip self-hosted sa-east-1
- AlertManager + custom Falco rules (apenas se security eng hired)

### 2.4 DR + RTO/RPO (Phase 3+)

| Service | RTO | RPO | Method |
|---|---|---|---|
| Scanner pool (Phase 3) | 15min | N/A (ephemeral) | ECS Fargate + autoscaler |
| Dashboard | 1h | 5min | Multi-AZ ECS + RDS Multi-AZ |
| API server | 1h | 5min | Same |
| Audit log | 4h | 1h (Phase 4: per-insert) | Sigstore Rekor immutable; multi-region S3 sync Phase 4 |
| RDS primary | 4h | 15min | Multi-AZ failover + automated snapshots 35d |
| Customer data export | 24h | 1h | LGPD compliance requirement |

DR drill: annual (Phase 3); quarterly (Phase 4). Published RTO/RPO em `status.cryptoct.com/dr` na Phase 3.

---

## 3. PostgreSQL multi-tenant isolation — Phase 3 ativação

### 3.1 Phase 2 (GitHub App)

Per-installation row isolation simples via `WHERE installation_id = ?`. Sem RLS, sem PgBouncer SESSION mode. Adequado até tenant count > 10.

### 3.2 Phase 3 ativação (SaaS dashboard launch)

**Princípio:** Every query touches a row → RLS policy enforces tenant_id check. Background jobs and admin paths via `SECURITY DEFINER` procedures only.

**PgBouncer config (session mode, not transaction):**
```ini
[databases]
cryptoct = host=cryptoct-rds.sa-east-1.rds.amazonaws.com port=5432 dbname=cryptoct

[pgbouncer]
pool_mode = session              # MANDATORY — transaction mode breaks SET LOCAL
listen_port = 6432
max_client_conn = 1000
default_pool_size = 50
reserve_pool_size = 10
server_reset_query = DISCARD ALL
```

**Tenant pinning at session start:**
```go
// internal/db/tenant_pinned_conn.go
func TenantPinnedConn(ctx context.Context, pool *pgxpool.Pool, tenantID string) (*pgxpool.Conn, error) {
    conn, err := pool.Acquire(ctx)
    if err != nil { return nil, err }
    _, err = conn.Exec(ctx, "SET LOCAL app.tenant_id = $1", tenantID)
    if err != nil {
        conn.Release()
        return nil, err
    }
    return conn, nil
}
```

**ent ORM query interceptor:**
```go
// internal/db/tenant_interceptor.go
type TenantInterceptor struct{}

func (i TenantInterceptor) Intercept(next ent.Querier) ent.Querier {
    return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
        tenantID, ok := ctx.Value(TenantIDKey).(string)
        if !ok {
            return nil, fmt.Errorf("tenant_id required for query: %T", query)
        }
        // Explicit reject empty tenantID BEFORE any DB roundtrip — prevents
        // empty-string equality bypass when middleware is forgotten on a new endpoint.
        if tenantID == "" {
            return nil, fmt.Errorf("tenant_id must not be empty for query: %T", query)
        }
        var current string
        client := ent.FromContext(ctx)
        // missing_ok=false: an unset session must RAISE, not silently return ''.
        row := client.QueryRow(ctx, "SELECT current_setting('app.tenant_id', false)")
        row.Scan(&current)
        if current != tenantID {
            return nil, fmt.Errorf("session not pinned to tenant %s; got %s", tenantID, current)
        }
        return next.Query(ctx, query)
    })
}
```

**RLS policies on tables:**
```sql
ALTER TABLE cboms ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON cboms
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE repos ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON repos
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_events
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Migrations run via separate cryptoct_admin role with BYPASSRLS attribute
-- App connects via cryptoct_app role WITHOUT BYPASSRLS

-- cryptoct_admin OPSEC runbook (Phase 3 hard blocker):
--   1. Credential in Vault under namespace `cryptoct/admin-rds` (4-eyes path required)
--   2. MFA hardware (YubiKey) obrigatório for any Vault read of admin credential
--   3. Migration PR requires CODEOWNERS approval from founder técnico + founder operacional (4-eyes)
--   4. Any PR touching `migrations/` OR adding `SECURITY DEFINER` / `BYPASSRLS` requires outside witness co-sign in Vault
--   5. EventBridge rule pages on-call IMMEDIATELY on `SET ROLE cryptoct_admin`, `CREATE USER`, `ALTER ROLE`, `BYPASSRLS` grant/revoke
--   6. Session recording (RDS CloudTrail data events) mandatory; cross-check em weekly audit
--   7. Vault-issued STS session is short-lived (≤30min) AND embeds tag `MigrationApproved=true` non-reattributable per §7.2 SCP pattern
```

**Background jobs via SECURITY DEFINER:**
```sql
CREATE OR REPLACE FUNCTION audit_merkle_anchor()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    tenant_row record;
BEGIN
    FOR tenant_row IN SELECT DISTINCT tenant_id FROM audit_events
                      WHERE created_at > now() - interval '1 hour'
                      AND anchored_at IS NULL
    LOOP
        -- Compute merkle root + Sigstore Rekor anchor
        ...
    END LOOP;
END;
$$;

GRANT EXECUTE ON FUNCTION audit_merkle_anchor() TO cryptoct_scheduler;
REVOKE ALL ON FUNCTION audit_merkle_anchor() FROM PUBLIC;
```

**Integration tests obrigatórios:**
```go
func TestEveryQueryHasRLS(t *testing.T) {
    // Create 2 tenants, insert data into each
    // Run EVERY API endpoint with tenant A context
    // Assert tenant B data NEVER returned
}

func TestSessionPinningPreservedAcrossPgBouncer(t *testing.T) { ... }
func TestReadReplicasHaveRLS(t *testing.T) { ... }
```

---

## 4. Audit log architecture

### 4.1 Phase 3 (current execution)

**Write path (DBA-resistant):**
```sql
CREATE OR REPLACE FUNCTION audit_log_append(
    p_tenant_id uuid,
    p_event_type text,
    p_actor_id text,
    p_payload jsonb
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    event_id uuid := gen_random_uuid();
BEGIN
    -- Reject mismatched p_tenant_id vs session context (binds signature to session).
    IF p_tenant_id IS DISTINCT FROM current_setting('app.tenant_id', false)::uuid THEN
        RAISE EXCEPTION 'audit_log_append: tenant_id mismatch between argument and session context';
    END IF;

    INSERT INTO audit_events (id, tenant_id, event_type, actor_id, payload_encrypted, created_at)
    VALUES (event_id, p_tenant_id, p_event_type, p_actor_id, encrypt_with_kek(p_payload, p_tenant_id), now());

    INSERT INTO audit_outbox (event_id, sync_status, created_at)
    VALUES (event_id, 'pending', now());

    PERFORM pg_notify('audit_outbox', event_id::text);

    RETURN event_id;
END;
$$;

GRANT EXECUTE ON FUNCTION audit_log_append TO cryptoct_app;
REVOKE INSERT, UPDATE, DELETE ON audit_events FROM cryptoct_app;
REVOKE ALL ON audit_outbox FROM cryptoct_app;
```

### Terraform locks for audit RDS (drift alarm required)

Plaintext lifetime inside the SECURITY DEFINER body becomes operator-accessible if any
RDS observability flag flips. Terraform MUST lock the following with EventBridge drift
alarms paging on-call:

- **Performance Insights: DISABLED** (parameter capture must remain off)
- **Enhanced Monitoring: DISABLED**
- **parameter_group: `log_statement = 'none'`** (NOT `'all'` or `'mod'`)
- **EventBridge rule:** alarm on parameter-group drift OR `enable_performance_insights`
  drift OR `enhanced_monitoring` drift → page on-call immediately.

**Rationale:** plaintext lifetime inside the SECURITY DEFINER body becomes
operator-accessible if any of these flags flip. The CLOUD Act language at 02:106 refers
to Phase 4 BYOK with `K-audit-tenant-{N}`, NOT to Phase 3 server-side `encrypt_with_kek`.
Without these Terraform locks + drift alarms, the Phase 3 posture overstates the
present claim.

**Event trigger blocking DBA mutations:**
```sql
CREATE OR REPLACE FUNCTION block_audit_mutations()
RETURNS event_trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_event_trigger_ddl_commands()
        WHERE object_identity = 'public.audit_events'
        AND command_tag IN ('ALTER TABLE', 'DROP TABLE', 'TRUNCATE')
    ) THEN
        RAISE EXCEPTION 'audit_events table is immutable; mutations require offline maintenance window';
    END IF;
END;
$$;

CREATE EVENT TRIGGER block_audit_mutations_trigger
ON ddl_command_end
EXECUTE FUNCTION block_audit_mutations();
```

**Hourly Merkle anchoring (Sigstore Rekor single anchor):**
```go
// internal/audit/merkle_worker.go
func HourlyMerkleAnchor(ctx context.Context) error {
    tenants := listActiveTenants(ctx)
    for _, t := range tenants {
        events := readHourlyEvents(ctx, t.ID)
        root := computeMerkleRoot(events)

        // Phase 3: sign with K-service (server-side)
        signature, err := signWithKService(ctx, root)
        if err != nil { return err }

        // Single anchor — Sigstore Rekor
        rekorEntry, err := uploadToRekor(ctx, root, signature)
        if err != nil {
            return fmt.Errorf("rekor anchor failed: %w", err)
        }

        storeAnchorReceipt(ctx, t.ID, root, signature, rekorEntry)
    }
    return nil
}
```

### 4.2 Phase 4 ativação (1º Enterprise LOI)

Adiciona:
- Multi-region S3 sync per-insert
- Customer KMS BYOK signing (K-audit-tenant-{N}) — sign substituído de K-service para customer key
- Triple anchor 3-of-3 quorum: Sigstore Rekor + RFC 3161 TSA DigiCert + RFC 3161 TSA e-Sec Brasil
- Long-term archive: SLH-DSA-SHA2-128s assinatura mensal sobre Merkle root anual
- Customer independent verification via `pqcheck audit-verify --rekor-witness --tsa-witness --kms-pubkey customer.pub --quorum-required 3`

---

## 5. Scanner sandboxing

### 5.1 Phase 1 (CLI on customer machine)

Sem sandboxing necessário — scanner roda na máquina do customer. Customer controla isolation.

### 5.2 Phase 2 (GitHub App)

AWS Lambda execution environment com task IAM least-privilege. Ephemeral por invocation. Sem gVisor necessário.

### 5.3 Phase 3 ativação (scanner-svc backend introduction)

ECS Fargate com:
- Task IAM least-privilege
- VPC endpoints para S3 + RDS
- Security groups deny-all default
- CloudTrail + AWS GuardDuty alerts

### 5.4 Phase 4 ativação (Enterprise multi-tenant scanner)

EKS pod security completo:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: scanner-job-$(uuid)
spec:
  serviceAccountName: scanner-job-sa
  runtimeClassName: gvisor             # gVisor sandbox
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 2000
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/scanner-restricted.json
  containers:
    - name: scanner
      image: cryptoct/scanner:0.1.0@sha256:abc...
      imagePullPolicy: Always
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          cpu: "2"
          memory: "2Gi"
          ephemeral-storage: "1Gi"
        requests:
          cpu: "500m"
          memory: "512Mi"
      volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: scan-input
          mountPath: /scan-input
          readOnly: true
        - name: scan-output
          mountPath: /scan-output
      env:
        - name: SCAN_TIMEOUT_SECONDS
          value: "300"
        - name: MAX_FILE_SIZE_MB
          value: "10"
        - name: MAX_FILES_PER_SCAN
          value: "50000"
  volumes:
    - name: tmp
      emptyDir:
        sizeLimit: 500Mi
        medium: Memory
    - name: scan-input
      emptyDir:
        sizeLimit: 100Mi
    - name: scan-output
      emptyDir:
        sizeLimit: 50Mi
```

**Network policy zero-egress:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scanner-zero-egress
spec:
  podSelector:
    matchLabels:
      app: scanner
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 52.94.5.0/24  # AWS S3 sa-east-1
    - ports:
        - protocol: TCP
          port: 443
    - to:
        - podSelector:
            matchLabels:
              app: postgres-pool
      ports:
        - protocol: TCP
          port: 5432
    - to:
        - ipBlock:
            cidr: 169.254.0.0/16
            except: ["169.254.169.254/32"]  # block IMDS
```

**mvn sub-sandbox via nsjail:**
```bash
nsjail \
    --mode o --user 65534 --group 65534 \
    --time_limit 60 --rlimit_as 1024 --rlimit_cpu 60 \
    --disable_clone_newnet --chroot /scan-input \
    --bindmount_ro /opt/maven:/opt/maven \
    --keep_caps --really_quiet \
    -- /opt/maven/bin/mvn help:effective-pom -Doutput=/scan-output/effective-pom.xml
```

**Seccomp profile** (allowlist syscalls): `profiles/scanner-restricted.json`.

---

## 6. Cloud Act risk + BYOK mitigation

### 6.1 Risk statement (sub-processor disclosure)

> AWS Inc and Cloudflare Inc are US-parented corporations subject to the US CLOUD Act (18 USC §2713), which obligates them to produce customer data hosted in any region — including AWS sa-east-1 — when served a US legal process. Despite Brazilian jurisdiction over the data plane, this jurisdictional reach can override LGPD residency commitments under certain circumstances. CryptoCT mitigates this risk through:
>
> 1. **BYOK (Bring Your Own Key) architecture for audit logs (Phase 4).** Customer-controlled K-audit-tenant-{N} keys are stored in customer's own AWS KMS sa-east-1 OR HashiCorp Vault OR Azure Key Vault OR on-prem HSM. Audit data is encrypted client-side; AWS receives only ciphertext.
>
> 2. **Customer data minimization (Phase 1+).** Source code is never persisted (only hashes + AST node types). Scanner pods are ephemeral with zero-egress network policy (Phase 4).
>
> 3. **Explicit disclosure.** This document is referenced in our DPA + Termos as required by LGPD Art. 6 VI + Art. 9 (transparência) + Art. 18; Art. 33 apenas quando sub-processador US-parented dispara transferência internacional.
>
> 4. **Roadmap commitment.** Phase 5+ evaluation of 100% BR-resident provider (Locaweb, Tivit, Algar Cloud) for data plane.

### 6.2 BYOK implementation — Phase 4 ativação

**Default Phase 4:** AWS KMS only + customer pubkey export (manual signing via offline KMS).

**On-demand (quando customer pedir):** HashiCorp Vault, Azure Key Vault, on-prem HSM.

Key operations:
- `generate_key(tenant_id, algorithm=ML-DSA-87) → key_handle`
- `sign(key_handle, merkle_root) → signature`
- `verify(key_handle_or_pubkey, merkle_root, signature) → bool`
- `rotate(old_handle, new_handle) → re-sign during 30-day overlap`
- `revoke(key_handle, reason) → archive pubkey; signing stops`
- `export_public_key(key_handle) → bytes`

Verify-after-revoke: pub key archived in Sigstore Rekor + S3 Object Lock; revocation also Rekor-anchored.

---

## 7. KMS safeguards — Phase 4 ativação

### 7.1 Multi-KMS scattered deletion

```terraform
# infra/terraform/audit-kms.tf — Phase 4 only
resource "aws_kms_key" "audit_kek_primary" {
  description              = "Audit log KEK — primary"
  deletion_window_in_days  = 30
  enable_key_rotation      = true
  policy = data.aws_iam_policy_document.audit_kek_primary.json
  tags = { Purpose = "audit-log", Tier = "primary" }
}

resource "aws_kms_key" "audit_kek_secondary" {
  description              = "Audit log KEK — secondary (scattered deletion)"
  deletion_window_in_days  = 30
  enable_key_rotation      = true
  tags = { Purpose = "audit-log", Tier = "secondary" }
}

resource "aws_kms_key" "audit_kek_tertiary" {
  description              = "Audit log KEK — tertiary"
  deletion_window_in_days  = 30
  enable_key_rotation      = true
  tags = { Purpose = "audit-log", Tier = "tertiary" }
}
```

### 7.2 4-eyes approval for key deletion

```yaml
{
  "Effect": "Deny",
  "Action": ["kms:ScheduleKeyDeletion", "kms:DisableKey"],
  "Resource": "arn:aws:kms:sa-east-1:*:key/audit-kek-*",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalTag/ApprovedDeletionWorkflow": "true"
    }
  }
}
```

**SCP-AUDIT-KMS-TAG-DENY** (Organizations-level, applied to all accounts touching audit KMS):

    Effect: Deny
    Action: ["iam:Tag*", "iam:Untag*", "sts:TagSession"]
    Resource: "*"
    Condition:
      StringLike:
        aws:PrincipalTag/CanScheduleKMSDeletion: "true"
      ArnLike:
        kms:RequestedKeyArn: "arn:aws:kms:sa-east-1:*:key/audit-kek-*"

The principal that holds `kms:ScheduleKeyDeletion` on `audit-kek-*` CANNOT write its own
`ApprovedDeletionWorkflow` tag — this turns the 4-eyes from a workflow promise into a
policy invariant.

Tag issuance flow:
1. Founder + outside witness co-sign deletion request in Vault (MFA + 2-of-2)
2. Vault issues a short-lived STS session whose session policy *embeds* the tag
   (non-reattributable — the tag cannot be applied separately to other principals)
3. CI never writes tags; it consumes the Vault-issued STS session

EventBridge alarms on `iam:Tag*`, `iam:Untag*`, and `sts:TagSession` calls (not only on
`kms:ScheduleKeyDeletion`) — drift detection at the policy layer, not the action layer.

GitHub OIDC compromise consideration: a compromised `id-token: write` workflow CANNOT
drive this sequence because Vault co-signature requires human MFA + outside witness.

Workflow: founder técnico opens PR → founder operacional approves → outside witness co-signs in Vault (MFA + 2-of-2) → Vault issues short-lived STS session embedding `ApprovedDeletionWorkflow=true` tag → CI consumes STS session, calls `kms:ScheduleKeyDeletion` → CloudTrail alert + PagerDuty → 30d cooling → final deletion logged + customer notified.

### 7.3 S3 Object Lock Compliance

```terraform
resource "aws_s3_bucket_object_lock_configuration" "audit_archive" {
  bucket = aws_s3_bucket.audit_archive.id
  # NOTE: retention varies per audit-row class via S3 lifecycle rules; see 02 §retention.
  # Default below is the AML/BCB baseline; per-class rules attached as separate
  # aws_s3_bucket_lifecycle_configuration resources keyed by object-tagging.
  rule {
    default_retention {
      mode = "COMPLIANCE"  # COMPLIANCE mode: root cannot override. Per-class basis cited in 02 §retention.
      years = 5            # AML (Lei 9.613/1998 Art. 10) + Resolução BCB 119/2021 + Circular 4.001/2020 baseline
    }
  }
}
### Per-class lifecycle rules (separate resources, not shown here):
#   - cardholder-data subset → PCI-DSS v4.0.1 Req. 10.5.1: 12 meses mínimo (spec) + 3y total (Visa/Mastercard guidance)
#   - PII geral fora de PLD/BCB/PCI → 30d tombstone (LGPD Art. 16 I carve-out: cumprimento de obrigação legal/regulatória pelo controlador)
# NO replication config (CRR disabled)
# NO lifecycle to Glacier (transition disabled)
# NO IAM policy permitting cross-region copy
```

CloudTrail alert on any Object Lock policy change → PagerDuty immediate.

---

## 8. Tails ceremônia OPSEC — Phase 4 ativação

### 8.1 Tails ISO pinning

```markdown
# scripts/ceremony/README.md

## Tails OS — Pinned Version

**Version:** Tails 6.x (atualizado quando cerimônia agendada)
**Download URL:** https://tails.net/install/expert/?p=tails-amd64-6.x.iso
**SHA-256:** registered in `tails-pinning.yaml` (committed by ≥2 of {founder, outside witness} via signed commit). Ceremony tool MUST refuse execution if `tails-pinning.yaml` is missing or signature verification fails.
**Gating CI (Phase 4 pre-trigger):** workflow `ceremony-pinning-gate.yml` verifies the YAML hash matches Tails official release SHA-256 fetched out-of-band; PR cannot merge to `main` without two-signer approval.
**GPG Fingerprint:** `A490 D0F4 D311 A415 3E2B B7CA DBB8 02B2 58AC D84F`
**Verification:** baixado e verified out-of-band em hardware separado por outside witness ANTES da cerimônia.

DO NOT use Tails latest if differs from pinned version. Update pin in this README + create ADR if upgrading.
```

### 8.2 Hardware dedicado

- 1× ThinkPad Carbon X1 ou equivalente, comprado especificamente para cerimônia
- NVMe encrypted full-disk em estado de fábrica
- Sem WiFi/Bluetooth (hardware switch off OR physical removal)
- Sem cellular modem
- Câmera coberta
- Armazenado em cofre quando não em uso

Pós-cerimônia: `nvme format /dev/nvme0n1 -s 1` (secure erase NVMe); reinstall Tails clean.

### 8.3 Anti-OPSEC

- Agenda NÃO publicizada (Slack DM apenas entre participantes; sem calendar shared)
- Lançamento HN coordenado para não coincidir com ceremony window (tag-push >24h antes do HN)
- Pen drive USB courier media rotated entre cerimônias; secureWipe pós-uso
- Boot Tails → cerimônia → boot normal upload → boot Tails secureWipe USB

### 8.4 Audit recording

- Cerimônia gravada via smartphone (vídeo + áudio)
- Upload pós-cerimônia para `s3://cryptoct-audit-recordings/` (Object Lock Compliance 10y)
- Transcrição cartório SP da ata digital
- Ata inclui: data + horário; participantes (foto + CPF/CNPJ via cartório auth); Tails ISO hash verificado; hardware serial number; outside witness ML-DSA pubkey + cartório attestation; final K-release pubkey + Rekor record

---

## 9. Defensive squatting (reduced scope)

### 9.1 Registries (4 + 3 domains)

| Registry | Names | Tipo |
|---|---|---|
| **PyPI** | `pqcheck` (real) | Real |
| **Docker Hub** | `cryptoct/pqcheck` (real) | Real |
| **GitHub org** | `cryptoct` | Real |
| **npm** | `@cryptoct/cli` | Real (caso SDK JS lance) |
| **Domains** | `cryptoct.com`, `cryptoct.com.br`, `pqcheck.dev` | Real |

**Phase 4+ (se Helm chart lança):** + Helm Artifact Hub `cryptoct`.

**Removed do scope** (eram defensive sweep desnecessário): Cargo (sem Rust port), RubyGems (sem Ruby port), Helm Hub (sem Helm público), Homebrew tap (deferred v0.3), typo defenses (cripto-ct.com, criptoct.com.br, cryptoCt.com, pqchek.dev, pqcheck.com.br — baixo signal:cost ratio para Python CLI).

**Custo total:** ~R$ 200-400/yr (vs R$ 1k-2k anterior).

### 9.2 Monitoring

- **Socket.dev** (free tier) — typosquat detection on PyPI/npm
- **Phylum** (free tier) — supply chain risk monitoring
- **GitHub Secret Scanning** + **Push Protection** habilitados

---

## 10. Sub-processor disclosure

```markdown
# CryptoCT Sub-Processor Disclosure

> Per LGPD Art. 6 VI + Art. 9 (transparência) + Art. 18; Art. 46 (segurança); Art. 33 apenas para transferência internacional onde aplicável. Última atualização: 2026-05-22.

## Categorias de processamento

CryptoCT processa dados de cliente em duas camadas:

1. **Data Plane (sa-east-1):** todos artefatos de cliente, audit logs, OAuth tokens, PII de usuário, CBOMs gerados (Phase 3+).
2. **Control Plane (Cloudflare):** apenas auth, rate-limit, webhook verify. NÃO armazena artefato cliente.

## Sub-processadores ativos por fase

### Phase 1-2 (CLI + GitHub App)

| Provedor | Função | Localização | LGPD status | Cloud Act exposure |
|---|---|---|---|---|
| AWS Inc | Lambda + S3 sa-east-1 | Brasil (US parent) | DPA assinado; Art. 33 disclosed | YES — mitigado por minimization |
| Cloudflare Inc | Workers stateless edge | Global edge (US parent) | DPA assinado; Workers não armazena cliente | YES — mitigado por stateless |
| GitHub Inc | Marketplace + Actions | US | DPA assinado | YES — apenas instalação metadata |
| Stripe Inc | Enterprise USD payments | US | DPA + LGPD addendum | YES — apenas Enterprise tier US-billed |
| Sigstore | Public transparency log (Rekor) | US/global | OSS project; apenas Merkle roots públicos | N/A — public ledger |

### Phase 3 ativação (SaaS launch)

Adiciona:
| Provedor | Função | Localização |
|---|---|---|
| Sentry Inc | Error tracking SaaS com PII scrub | US | DPA |
| Datadog Inc OR Honeycomb | Metrics + traces SaaS | US | DPA |
| Auth0/Clerk | OIDC + WebAuthn | US | DPA |
| PagerDuty | Incident management | US | DPA — apenas alert metadata |
| Intigriti | Bug bounty | EU (BE) | GDPR + DPA |
| Vanta OR Drata | Compliance automation | US | DPA + apenas metadata |
| Asaas (Brasil) — quando 3º BR customer pedir Pix | Pix recurring + boleto BR | Brasil | BACEN-compliant + DPA — BR-resident |

### Phase 4 ativação (1º Enterprise LOI)

Adiciona:
| Provedor | Função | Localização |
|---|---|---|
| DigiCert | RFC 3161 TSA backup | US | Public TSA — apenas timestamps |
| e-Sec Brasil | RFC 3161 TSA primary | Brasil | ICP-Brasil acreditada — BR-resident |
| NFE.io OR Omie (se >20 NF-e/mo) | NF-e BR | Brasil | Receita Federal compliant — BR-resident |

## Cliente direitos (LGPD Art. 18)

- Acesso (1-click via dashboard Phase 3+)
- Correção (via support)
- Anonimização/eliminação por classe (eventos PLD/AML 5y via Lei 9.613/1998 Art. 10, BCB-regulados 5y via Res. BCB 119/2021 + Circ. 4.001/2020, cardholder PCI 12 meses mínimo / 3y guidance, PII geral 30d) — todos com **LGPD Art. 16 I carve-out** documentado (cumprimento de obrigação legal ou regulatória pelo controlador)
- Portabilidade (export 1-click Phase 3+)
- Revogação de consentimento (immediate effect, exceto para audit log retention legal obligation)
- Eliminação de dados pessoais tratados com base no consentimento (30d)

Contato DPO: `dpo@cryptoct.com` (resposta em 15 dias úteis).
```

---

## 11. Bug bounty — Phase 3 ativação

```markdown
# CryptoCT Bug Bounty Program (Intigriti)

> Live a partir de Phase 3 (mês 6+, após Series Seed signed). SLA: triage 24h, fix critical 30d, high 90d, medium 180d.

## Scope

**In scope:**
- pqcheck CLI (PyPI package, GitHub source)
- GitHub App cbom-diff
- Dashboard SaaS (app.cryptoct.com, api.cryptoct.com)
- Public infrastructure (status.cryptoct.com, keys.cryptoct.com, docs.cryptoct.com)

**Out of scope:**
- Social engineering against founders/staff
- DoS attacks (rate-limit testing OK; sustained DoS NOT OK)
- Automated scanner output without working PoC
- Third-party services (Stripe, Asaas, AWS, Cloudflare, GitHub native vulns)
- Findings already in public disclosure (SECURITY.md Transitive PQC Risk)
- Theoretical risks without exploitation path
- Subdomain takeover without active exploitation
- Self-XSS

## Payouts (USD)

| Severity | Payout range | Examples |
|---|---|---|
| Critical | $5,000 - $15,000 | RCE in scanner pool, audit log forgery, cross-tenant data leak |
| High | $1,000 - $5,000 | Stored XSS, IDOR enabling cross-tenant, account takeover |
| Medium | $250 - $1,000 | Reflected XSS, CSRF, info disclosure of non-PII |
| Low | $50 - $250 | Missing security headers, verbose errors |

## Safe-harbor

Researchers acting in good faith under this program are not subject to legal action under Marco Civil da Internet (Art. 7-8), LGPD Art. 7 (legitimate interest in security research), US CFAA, DMCA Section 1201(j). Reviewed by legal counsel.

## Reporting

- Intigriti platform: https://app.intigriti.com/researcher/programs/cryptoct
- Direct email: `security@cryptoct.com` (PGP key in SECURITY.md)
```

---

## 12. Pen-test annual — Phase 3 ativação

**Cadence:** annual (Phase 3); quarterly red-team via fractional CISO se Phase 4 ativada.

**Phase 3 annual scope** (rotating yearly):
- Year 1: Multi-tenant isolation (RLS + scanner pods) + supply chain
- Year 2: BYOK customer KMS integration security (se Phase 4 ativada)
- Year 3: Compliance posture (LGPD DPIA review, SOC 2 control sampling)

**Phase 4 trimestral quando customer LOI Enterprise:**
- Q1: K-release ceremony OPSEC + supply chain
- Q2: Multi-tenant isolation deep dive
- Q3: BYOK customer KMS integration
- Q4: Compliance posture

**Deliverable:** report + action items + tabletop drill with founders.

**Owner:** annual = external pen-test firm (~USD 15-25k); quarterly = fractional CISO (hired via Intigriti vCISO network OR independent consultant).

---

## 13. Compliance ops (LGPD-specific) — MANTIDO Phase 1+ (mandatory)

### 13.1 DPIA (Data Protection Impact Assessment)

Mandatory por LGPD Art. 38 desde mês 1. Documento completo em `docs/compliance/dpia-2026.md`. Inclui:
- Description of processing activities
- Necessity + proportionality assessment
- Risks to data subjects
- Measures envisaged to address risks
- Anonymization techniques (file hash + AST node-types, no source content)
- Sub-processor disclosure (cross-ref §10)

### 13.2 ROPA (Records of Processing Activities)

Mandatory por LGPD Art. 37 desde mês 1. Mantido em `docs/compliance/ropa-2026.md`. Atualizado a cada novo sub-processador.

### 13.3 DPO fractional contracts

- Mês 1+: DPO fractional contratado (0.2-0.4 FTE, ~USD 1.5-3k/mês)
- Responsibilities: ANPD interface, DSR (Data Subject Request) handling, DPIA maintenance, incident notification coordination
- Contato público: `dpo@cryptoct.com`

### 13.4 Customer data flows visualization

`docs/compliance/data-flows-diagram.svg` — visual mapping de cada classificação de dado através dos sub-processadores, com retention policies. Atualizado em cada Phase ativação.
