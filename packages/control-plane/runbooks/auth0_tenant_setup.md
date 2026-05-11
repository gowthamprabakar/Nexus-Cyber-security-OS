# Auth0 tenant setup — operator runbook

Owner: control-plane on-call · Audience: a human operator with admin access to the Auth0 organization · Last reviewed: 2026-05-11.

This runbook is the **one-time setup** per environment (`dev` / `staging` / `prod`) that lights up Auth0 as the Nexus IdP. Once it's done, every customer flows through SSO + MFA + SCIM without further manual setup, except for SAML enterprise onboardings (Section 5).

> **Status:** v0.1. Phase 1c will move steps 2–4 + 7 into a Terraform module so the bootstrap becomes one `terraform apply`. Today it's manual on purpose — bootstrapping while the configuration shape is still settling avoids re-IaCing twice.

---

## Prerequisites

- An Auth0 administrator account with rights to create tenants and Applications in the target environment.
- The `Auth0 CLI` (`auth0`) installed and authenticated against the target tenant. ([Install instructions](https://github.com/auth0/auth0-cli).)
- Access to the deployment's `1password` vault entry for credentials storage (we never check Auth0 secrets into git).
- This control-plane checkout, with `uv sync` clean.

---

## 1. Create the Auth0 tenant

One-time per environment.

1. Sign in to <https://manage.auth0.com> as an admin.
2. Click your avatar → **Create tenant**.
3. Tenant name: `nexus-<env>` (e.g. `nexus-prod`). Region: `US-1` (Phase 1; multi-region defers to Phase 2 GA hardening).
4. Click **Create**.
5. Record the tenant domain (e.g. `nexus-prod.us.auth0.com`) into 1password under `nexus/auth0/<env>/domain`.

---

## 2. Create the Nexus control-plane Application

The Application is the OIDC client our control plane talks to.

1. In the new tenant: **Applications → Applications → Create Application**.
2. Name: `nexus-control-plane`. Type: **Regular Web Application**. Click **Create**.
3. In the **Settings** tab, set:
   - **Allowed Callback URLs**: `https://api.nexus.app/auth/callback` (prod) — also include staging if you're sharing a tenant.
   - **Allowed Logout URLs**: `https://app.nexus.app/logout`.
   - **Allowed Web Origins**: `https://app.nexus.app`.
   - **Token Endpoint Authentication Method**: **Post**.
4. Scroll to **Advanced Settings → Grant Types** and tick:
   - `Authorization Code`
   - `Refresh Token` (lets `/auth/me` survive ~24h without forcing re-login)
5. **Save Changes** at the bottom.
6. Record the Application's **Client ID** and **Client Secret** in 1password under `nexus/auth0/<env>/control_plane_client`.

---

## 3. Configure the API audience

The access tokens our agents verify must carry our API as `aud`.

1. **Applications → APIs → Create API**.
2. Name: `Nexus API`. Identifier (audience): `https://api.nexus.app` (this becomes `aud` in JWTs).
3. Signing algorithm: **RS256**.
4. **Create**.
5. In the new API's **Settings**, enable **Allow Skipping User Consent**.

---

## 4. Inject `tenant_id` and `roles` as custom claims

Per F.4 Q2: tenant + roles live under Auth0-namespaced custom claims, NOT in `sub` or `email`.

1. **Actions → Library → Create Custom Action → Build from scratch**.
2. Name: `inject-nexus-claims`. Trigger: `post-login`.
3. Paste:

   ```javascript
   exports.onExecutePostLogin = async (event, api) => {
     const namespace = 'https://nexus.app';
     // tenant_id is sourced from the user's app_metadata (set by SCIM at provisioning time).
     const tenantId = event.user.app_metadata?.tenant_id;
     if (tenantId) {
       api.idToken.setCustomClaim(`${namespace}/tenant_id`, tenantId);
       api.accessToken.setCustomClaim(`${namespace}/tenant_id`, tenantId);
     }
     // roles come from Auth0 RBAC roles or from app_metadata.roles fallback.
     const roles =
       (event.authorization?.roles?.length
         ? event.authorization.roles
         : event.user.app_metadata?.roles) || [];
     api.idToken.setCustomClaim(`${namespace}/roles`, roles);
     api.accessToken.setCustomClaim(`${namespace}/roles`, roles);
   };
   ```

4. **Deploy**.
5. **Actions → Flows → Login** → drag the new Action into the flow → **Apply**.

> Verify: log in with a test user via `/auth/login` and confirm the issued token (decode with `auth0 test token`) carries `https://nexus.app/tenant_id` and `https://nexus.app/roles`.

---

## 5. SAML connection for an enterprise customer

Repeat this section per enterprise customer that supplies their own IdP.

1. **Authentication → Enterprise → SAML → Create Connection**.
2. Name: `cust-<customer-slug>-saml`.
3. **Sign In URL**: from the customer's IdP-supplied metadata (`SingleSignOnService` endpoint).
4. **X509 Signing Certificate**: paste the customer's IdP cert (`X509Certificate` element from their metadata).
5. **Email attribute**: usually `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`.
6. **Save**.
7. Enable the connection for the `nexus-control-plane` Application: **Applications → nexus-control-plane → Connections** → tick the new SAML connection.
8. Send the customer Auth0's **SP metadata** (download from the connection's **Setup** tab) so they can register us in their IdP.
9. Smoke test: from the customer's IdP, initiate an IdP-initiated login → expect a redirect to `/auth/callback` → JSON `{"status":"logged_in"}` with the session cookie set.

---

## 6. SCIM endpoint configuration

Auth0 will POST new users to our SCIM endpoint as it provisions them.

1. **Authentication → SCIM (Outbound) → Add Provisioning Endpoint**.
2. Service Provider URL: `https://api.nexus.app/scim/v2/Users`.
3. Authentication: **HMAC**.
4. Generate a secret with `python -c "import secrets; print(secrets.token_urlsafe(32))"` and paste into Auth0's secret field.
5. Store the same secret in 1password under `nexus/auth0/<env>/scim_hmac_secret` (also written into the control-plane env vars — Phase 1c moves it into AWS Secrets Manager).
6. Enable **User provisioning** + **User deactivation**. Disable **Group provisioning** (deferred to Phase 1c; we currently key off the `tenant_id` claim, not Auth0 groups).
7. Map attributes:
   - SCIM `userName` ← `email`.
   - SCIM `externalId` ← `user_id`.
   - SCIM `urn:ietf:params:scim:schemas:extension:nexus:2.0:User.tenantId` ← `app_metadata.tenant_id`.
   - SCIM `urn:ietf:params:scim:schemas:extension:nexus:2.0:User.role` ← `app_metadata.role` (defaults to `auditor`).
8. Rotate the secret quarterly — calendar reminder in PagerDuty's `nexus-control-plane-rotation` schedule.

---

## 7. Enforce MFA at the tenant level

F.4 Task 9's `require_mfa` gate trusts Auth0's `amr` claim. Auth0 only emits `amr=["mfa"]` if MFA actually happened.

1. **Security → Multi-factor Auth** → enable for the tenant.
2. Tick at least **One-time Password** (TOTP) and **WebAuthn**. Leave SMS off (well-known SS7 attack surface).
3. **Policy**: **Always** for production, **Use Adaptive MFA** for dev/staging.
4. **Save**.
5. Verify by logging in a fresh test user: expect a TOTP prompt → token's `amr` contains `"mfa"`.

---

## 8. Verify the integration end-to-end

Run the smoke sequence before declaring done.

```bash
export NEXUS_AUTH0_DOMAIN=nexus-<env>.us.auth0.com
export NEXUS_AUTH0_CLIENT_ID=...
export NEXUS_AUTH0_CLIENT_SECRET=...
export NEXUS_AUTH0_AUDIENCE=https://api.nexus.app
export NEXUS_SCIM_HMAC_SECRET=...
uv run pytest packages/control-plane -q
```

Then manually:

1. Visit `https://api.nexus.app/auth/login`. Expect a redirect to Auth0.
2. Sign in with a test user; satisfy MFA.
3. Land on `/auth/callback`; expect `200 OK` with the `nexus_session` cookie set.
4. `curl -b "nexus_session=<cookie>" https://api.nexus.app/auth/me` — expect a JSON body with `sub`, `tenant_id`, `roles`, `amr`.
5. `curl -b ... https://api.nexus.app/tenants/me` — expect your tenant record.

If you see `mfa.required.failure` in `audit.jsonl` when you tried an admin-scoped action, the MFA gate is working as intended; satisfy MFA and retry.

---

## Common failures

| Symptom                                      | Likely cause                                            | Fix                                                          |
| -------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------ |
| `/auth/callback` returns 401                 | Allowed Callback URLs missing the env's URL             | Section 2.3                                                  |
| `/auth/me` returns 401 with "missing kid"    | Action 4 not deployed; token has no `kid` header        | Re-deploy the Action and re-issue tokens                     |
| `POST /tenants` returns 403 ("MFA required") | User satisfied password but skipped MFA                 | Confirm MFA factors are enrolled for the account; re-login   |
| SCIM POST returns 401                        | HMAC mismatch — either Auth0 secret rotated, ours stale | Rotate both sides simultaneously (Section 6.8)               |
| SAML callback loops back to IdP              | Customer's `X509` cert reset on their side              | Pull fresh metadata from the customer and reload Section 5.4 |

---

## Cleanup if you need to start over

```bash
# Auth0 tenant deletion is irreversible. Confirm you mean it.
auth0 tenants delete nexus-<env>
```

Re-running this runbook against a fresh tenant should reproduce a working setup in under 30 minutes.

---

## See also

- [F.4 plan](../../../docs/superpowers/plans/2026-05-11-f-4-auth-tenant-manager.md) — task index + ADR pointers.
- [ADR-002](../../../docs/_meta/decisions/ADR-002-charter-as-context-manager.md) — audit-chain requirement.
- [ADR-004](../../../docs/_meta/decisions/ADR-004-fabric-layer.md) — `tenant_id` propagation across the fabric.
