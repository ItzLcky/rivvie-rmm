-- Single sign-on for technicians (OpenID Connect) and passkeys (WebAuthn) as a second factor.

-- An OIDC identity provider an admin configured. The client secret is sealed with RMM_DATA_KEY
-- when that is set (`secret_sealed`), like the other stored credentials.
CREATE TABLE sso_providers (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The button label on the sign-in page.
    name              text NOT NULL UNIQUE,
    preset            text NOT NULL DEFAULT 'custom' CHECK (preset IN ('custom', 'entra', 'google')),
    issuer            text NOT NULL,
    client_id         text NOT NULL,
    client_secret     bytea NOT NULL,
    secret_sealed     boolean NOT NULL DEFAULT false,
    scopes            text NOT NULL DEFAULT 'openid email profile',
    enabled           boolean NOT NULL DEFAULT true,
    -- The ID token claim that lists the user's groups (a dotted path reaches into objects).
    groups_claim      text NOT NULL DEFAULT 'groups',
    -- Create an account on first sign-in when the email matches nobody.
    jit               boolean NOT NULL DEFAULT false,
    -- Role and client access follow the group mappings at every sign-in.
    group_sync        boolean NOT NULL DEFAULT false,
    -- Role for a user none of the mappings matches. NULL: such a user can't sign in through
    -- this provider (when group_sync is on) or can't be created (JIT).
    default_role      text CHECK (default_role IN ('admin', 'technician', 'readonly')),
    -- Only these email domains may sign in (empty = any the provider vouches for).
    allowed_domains   text[] NOT NULL DEFAULT '{}',
    -- Entra ID: the tenants whose users may sign in. Required for the multi-tenant endpoints.
    allowed_tenants   text[] NOT NULL DEFAULT '{}',
    -- The provider doesn't send `email_verified` but only issues tokens for verified addresses
    -- (Entra ID restricted to the tenants above).
    trust_email       boolean NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- Which IdP group gives which role and clients.
CREATE TABLE sso_group_maps (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id         uuid NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    group_value         text NOT NULL,
    role                text NOT NULL CHECK (role IN ('admin', 'technician', 'readonly')),
    -- Granted on top of the role's defaults.
    extra_permissions   text[] NOT NULL DEFAULT '{}',
    all_clients         boolean NOT NULL DEFAULT false,
    client_ids          uuid[] NOT NULL DEFAULT '{}',
    UNIQUE (provider_id, group_value)
);

-- An account linked to an identity at a provider; `subject` is the provider's stable id.
CREATE TABLE user_identities (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id    uuid NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    subject        text NOT NULL,
    email          text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at  timestamptz,
    UNIQUE (provider_id, subject),
    UNIQUE (provider_id, user_id)
);
CREATE INDEX ON user_identities (user_id);

-- A sign-in in progress between the redirect to the provider and its callback. Single use;
-- only hashes of `state` and of the browser-binding cookie are kept.
CREATE TABLE sso_login_states (
    state_hash     bytea PRIMARY KEY,
    binding_hash   bytea NOT NULL,
    provider_id    uuid NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    nonce          text NOT NULL,
    code_verifier  text NOT NULL,
    next           text NOT NULL DEFAULT '/',
    expires_at     timestamptz NOT NULL
);

-- A session opened by SSO. The identity provider did the second factor, so these sessions
-- don't need our own 2FA set up; removing the provider ends them.
ALTER TABLE user_sessions ADD COLUMN sso_provider_id uuid REFERENCES sso_providers(id) ON DELETE CASCADE;

-- Break-glass: signs in with a password even when SSO is required, and is never changed by
-- group mappings.
ALTER TABLE users ADD COLUMN sso_exempt boolean NOT NULL DEFAULT false;
-- Created by SSO: its password is random and unknown.
ALTER TABLE users ADD COLUMN sso_only boolean NOT NULL DEFAULT false;
-- Password sign-in is refused for everyone but break-glass accounts.
ALTER TABLE company_settings ADD COLUMN sso_required boolean NOT NULL DEFAULT false;

-- Passkeys (WebAuthn credentials), a second factor beside TOTP. `passkey` is the serialised
-- public credential (public key, signature counter, flags): nothing secret.
CREATE TABLE user_passkeys (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name           text NOT NULL,
    credential_id  bytea NOT NULL UNIQUE,
    passkey        jsonb NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_used_at   timestamptz
);
CREATE INDEX ON user_passkeys (user_id);
