# Single sign-on and passkeys

Technicians can sign in with an OpenID Connect identity provider, and protect password sign-ins with passkeys (WebAuthn) as well as, or instead of, a TOTP app. SAML is out of scope for now.

## OIDC sign-in

Admins add providers under **Settings → Single sign-on** (`/api/settings/sso/...`). Entra ID and Google have presets; any OIDC provider with discovery (`/.well-known/openid-configuration`) works. The client secret is encrypted with `RMM_DATA_KEY` when it is set and never returned by the API. Register `${RMM_PUBLIC_URL}/api/auth/sso/callback` as the redirect URI (the settings page shows it).

The flow is the authorization code flow with PKCE (S256):

1. `GET /api/auth/sso/{id}/start` stores a single-use row (hashes of `state` and of a browser-binding cookie, the nonce, the PKCE verifier, the post-login path; ten minutes) and redirects to the provider. The binding cookie (`rmm_sso`, HttpOnly, SameSite=Lax, scoped to `/api/auth/sso`) makes a callback only valid in the browser that began it.
2. `GET /api/auth/sso/callback` consumes the state, exchanges the code (client secret by HTTP Basic or in the form, whichever the provider's discovery document advertises) and validates the ID token (`oidc.rs`): the signature against the provider's JWKS (cached an hour; an unknown `kid` refetches at most once a minute), `iss`, `aud` (and `azp` when there are several), `exp`, `nbf`, `iat` with 60 s of leeway, and the `nonce`. Only asymmetric algorithms (RS256/384/512, PS256/384/512, ES256/384 and EdDSA) are accepted, chosen from a fixed list, never from the key. Discovery, JWKS and token requests refuse plain `http` except for localhost, follow no redirects and are capped at 1 MB; a provider served over https can't name an `http` endpoint (the code and client secret would go to whatever listens on the machine).
3. The account is resolved and a session opened by the same code as a password sign-in (`open_session`), with the provider recorded on the session. Failures redirect to `/login?sso_error=<code>`. Once the state and the browser binding are valid, a failure is audited (`auth.sso_failed`, with the reason) and counted against a limit of its own (`sso_callback`, per IP, separate from password sign-ins); junk requests to the callback with no valid state are neither, so a page that makes browsers hit it can't fill the audit log or lock anyone out.

An SSO session counts as having a second factor (including for the password vault): the identity provider owns MFA policy, so such a session never has to set up TOTP here. Removing or disabling a provider, or changing its issuer, client id, allowed tenants or domains or email trust, ends the sessions it vouched for; a changed issuer or client id also drops its linked identities (subjects only mean something to the issuer and client that issued them; Entra's differ per application), so people link again by email, and the client secret has to be entered again with a new issuer.

### Entra ID

The issuer is `https://login.microsoftonline.com/<tenant id>/v2.0`. The multi-tenant endpoints (`organizations`, `common`) publish a discovery issuer with a `{tenantid}` placeholder; the token's `iss` must equal that template filled in with the token's own `tid`. Any Microsoft tenant's users hold validly signed tokens there, so a provider on a multi-tenant endpoint **must** list the tenant ids allowed to sign in, and the tid is checked against that list. Entra sends no `email_verified` claim; with the preset the address is believed (`trust_email`) for members of the tenants named (the tenants' admins are trusted to control `mail`), and `preferred_username` stands in for a missing `email`. A guest (a token whose `idp` isn't the tenant itself) is never believed: the address is whatever the inviter typed. Groups arrive as object IDs in the `groups` claim; a user in too many groups gets an overage pointer instead; with group sync on that refuses the sign-in and changes nothing, rather than guessing at their groups.

### Accounts, linking and groups

- A sign-in is matched first by the provider's stable `sub` (table `user_identities`), so a changed email address doesn't matter.
- A first sign-in links an **existing** account only through an email address the provider vouches for (`email_verified`, or a trusted provider). An account already linked to another identity at that provider can't be linked again, so a second identity claiming the address doesn't take the account over, and break-glass accounts are never linked by email at all.
- The **Google** preset needs allowed domains (anyone has a Google account) and requires the token's `hd` (Workspace domain) to be one of them; a personal account on a company address has none.
- With *Create accounts at first sign-in* (JIT) on, an unknown address gets an account with a random password nobody knows (`sso_only`). Without a mapped group or a default role nobody is created.
- *Allowed email domains* restrict who may sign in per provider.
- With *Role and clients follow IdP groups* on, each sign-in sets the account's role, extra permissions and clients from the mappings (`sso_group_maps`): the highest role among the matching groups, the union of their clients and extra permissions (added to the role's defaults). A user no mapping matches gets the provider's *default role* (technician or read-only, never admin; no clients), or, if there is none, can't sign in. Someone who had signed in through the provider before and is now in none of the groups is demoted to read-only with no clients and loses the sessions it vouched for; a first sign-in that matches nothing changes nothing, so trying SSO once never demotes an account. Group values compare case-insensitively.
- **Break-glass accounts** (Users → *Allow password sign-in*) are never changed by group mappings, and keep signing in with a password when SSO is required.
- **Require SSO** (`company_settings.sso_required`) refuses password sign-ins for everyone else. The server won't turn it on, or take away the last provider, or un-mark or disable the last break-glass admin, if that would leave nobody able to sign in. A password sign-in that is refused because SSO is required answers exactly like a wrong password, so it doesn't confirm that the password was right.

Audit actions: `auth.login` (`via: sso`), `auth.sso_link`, `auth.sso_access_sync`, `auth.sso_failed`, `user.create` (`via: sso`), `sso.provider_create|update|delete`, `sso.maps_update`, `sso.required`, `user.sso_exempt`.

## Passkeys

`/account` lists, adds, renames and removes passkeys (`/api/auth/passkeys...`); adding or removing one asks for the password, like TOTP setup. Credentials are stored as the public `Passkey` JSON from `webauthn-rs` (public key, signature counter, flags) in `user_passkeys`.

The relying party id is the host of `RMM_PUBLIC_URL` and the origin is that URL, so passkeys need a host name (not an IP address) and only work where the dashboard is reached at its public address. Ceremony state (registration and sign-in challenges) is kept in memory for five minutes, is single use, and is capped per user (five pending, the oldest replaced) so one account can't fill the table.

Sign-in with a passkey-protected account is: password → `401 {mfa_required, methods: {totp, passkey}}` → the browser asks `POST /api/auth/login/passkey` (password again) for a challenge, signs it, and resends `/api/auth/login` with `passkey: {ceremony_id, credential}`. A TOTP code or a recovery code works in the same place. A passkey satisfies a required second factor (admins, or everyone with *Require 2FA*); the first one also signs out the account's other sessions and, when there is no TOTP to have made them, creates the recovery codes. Removing the last factor removes the recovery codes; an admin's *Reset 2FA* and `rmm-server reset2fa` remove TOTP, passkeys and recovery codes together.

## Left out

SAML, passwordless (discoverable) passkey sign-in, group sync from userinfo or Graph (Entra overage), SCIM.
