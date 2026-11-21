-- Client documentation and the password vault (docs/design/documentation.md): MSP-wide
-- document categories and templates, documents pointing at a category instead of a free-text
-- one, and a per-client vault of credentials that documents link to.

-- ---------------------------------------------------------------------------
-- Categories. Seeded with fixed ids; every distinct free-text category already in use
-- becomes a row too, and the documents point at it.
-- ---------------------------------------------------------------------------
CREATE TABLE doc_categories (
    id          uuid PRIMARY KEY,
    name        text NOT NULL,
    position    integer NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX doc_categories_name ON doc_categories (lower(name));

INSERT INTO doc_categories (id, name, position) VALUES
    ('00000000-0000-4000-8003-000000000001', 'Network', 0),
    ('00000000-0000-4000-8003-000000000002', 'Infrastructure', 1),
    ('00000000-0000-4000-8003-000000000003', 'Accounts & access', 2),
    ('00000000-0000-4000-8003-000000000004', 'Applications', 3),
    ('00000000-0000-4000-8003-000000000005', 'Backup & recovery', 4),
    ('00000000-0000-4000-8003-000000000006', 'Vendors', 5),
    ('00000000-0000-4000-8003-000000000007', 'Procedures', 6),
    ('00000000-0000-4000-8003-000000000008', 'Onboarding', 7);

-- Free-text categories compare case-insensitively (the old list sorted that way); the first
-- spelling alphabetically wins, after the seeded ones.
INSERT INTO doc_categories (id, name, position)
SELECT gen_random_uuid(), c.name, 7 + row_number() OVER (ORDER BY lower(c.name))
  FROM (SELECT DISTINCT ON (lower(btrim(category))) btrim(category) AS name
          FROM client_docs WHERE btrim(category) <> ''
         ORDER BY lower(btrim(category)), btrim(category)) c
 WHERE NOT EXISTS (SELECT 1 FROM doc_categories d WHERE lower(d.name) = lower(c.name));

ALTER TABLE client_docs ADD COLUMN category_id uuid REFERENCES doc_categories(id) ON DELETE SET NULL;
UPDATE client_docs d SET category_id = c.id FROM doc_categories c WHERE lower(c.name) = lower(btrim(d.category));
ALTER TABLE client_docs DROP COLUMN category;
CREATE INDEX ON client_docs (client_id, category_id);

-- ---------------------------------------------------------------------------
-- Templates: a Markdown body with blocks and {{placeholders}}, copied when a page is started.
-- ---------------------------------------------------------------------------
CREATE TABLE doc_templates (
    id           uuid PRIMARY KEY,
    name         text NOT NULL,
    category_id  uuid REFERENCES doc_categories(id) ON DELETE SET NULL,
    description  text NOT NULL DEFAULT '',
    body         text NOT NULL DEFAULT '',
    created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX doc_templates_name ON doc_templates (lower(name));

INSERT INTO doc_templates (id, name, category_id, description, body) VALUES
('00000000-0000-4000-8004-000000000001', 'Network overview', '00000000-0000-4000-8003-000000000001',
 'Internet, addressing, VLANs, firewall and switches.', $md$# Network overview: {{client.name}}

_Last reviewed {{date}} by {{user.name}}._

## Internet

```fields
ISP:
Circuit / account number:
Public IP addresses:
ISP support:
```

## Addressing

```fields
LAN subnet:
Gateway:
DNS servers:
DHCP server:
DHCP range:
Static range:
```

## VLANs

| VLAN | Name | Subnet | Purpose |
|---|---|---|---|
| 1 | Default | | |
| | | | |

## Firewall

```fields
Make and model:
Firmware:
Management address:
```

```credential
label: Firewall admin
```

## Switches

| Name | Model | Management IP | Location |
|---|---|---|---|
| | | | |

```credential
label: Switch admin
```

## VPN, port forwards and static routes

```callout info
List every inbound port forward with the reason for it, and any site-to-site tunnels.
```
$md$),
('00000000-0000-4000-8004-000000000002', 'Wi-Fi', '00000000-0000-4000-8003-000000000001',
 'SSIDs, the controller and the keys for staff and guests.', $md$# Wi-Fi: {{client.name}}

| SSID | Bands | Security | VLAN | For |
|---|---|---|---|---|
| | 2.4 / 5 GHz | WPA2/WPA3 | | Staff |
| | 2.4 / 5 GHz | WPA2 | | Guests |

```fields
Controller:
Access points:
Management address:
```

```credential
label: Wi-Fi controller admin
```

## Staff network

```credential
label: Staff Wi-Fi key
```

## Guest network

```credential
label: Guest Wi-Fi key
```

```callout info
When the guest key changes, update the credential above and the sign at reception.
```
$md$),
('00000000-0000-4000-8004-000000000003', 'Server', '00000000-0000-4000-8003-000000000002',
 'One server: role, hardware, services, access and maintenance.', $md$# Server: hostname

```callout info
Use **Insert block → Device** to link this server's agent, so its state shows here.
```

```fields
Role:
Operating system:
IP address:
Hardware / host:
Location:
Warranty until:
```

## Services

| Service | Port | Notes |
|---|---|---|
| | | |

## Access

```credential
label: Local administrator
```

```credential
label: Out-of-band management (iDRAC / iLO / IPMI)
```

## Backups

- What is backed up:
- Where to:
- Last restore test:

## Maintenance

```callout warning
Note the reboot window and anything that has to be stopped first.
```
$md$),
('00000000-0000-4000-8004-000000000004', 'Microsoft 365 tenant', '00000000-0000-4000-8003-000000000003',
 'Tenant details, admin accounts, security baseline and domains.', $md$# Microsoft 365: {{client.name}}

```fields
Tenant name:
Tenant ID:
Primary domain:
Licences:
Bought through:
Admin centre: https://admin.microsoft.com
```

## Admin accounts

```credential
label: Global admin
```

```credential
label: Break-glass account
```

```callout danger
The break-glass account is excluded from conditional access. Use it only when every other admin is locked out, and tell the client when you do.
```

## Security baseline

- [ ] MFA required for every user
- [ ] Conditional access (or security defaults) on
- [ ] Legacy authentication blocked
- [ ] Unified audit log on
- [ ] External forwarding blocked
- [ ] Self-service password reset set up

## Domains and DNS

| Domain | Registrar | MX | SPF | DKIM | DMARC |
|---|---|---|---|---|---|
| | | | | | |
$md$),
('00000000-0000-4000-8004-000000000005', 'Line-of-business application', '00000000-0000-4000-8003-000000000004',
 'An application the client runs on: vendor, licences, access, installs and updates.', $md$# Application name

```fields
Vendor:
Version:
Licences / seats:
Renewal date:
Installed on:
Database:
Vendor support:
Client owner:
```

## Access

```credential
label: Application admin
```

```credential
label: Vendor support portal
```

## Installing on a workstation

1. Where the installer comes from:
2. Settings to choose:
3. How to check it works:

## Updates

```callout warning
Check with the vendor before updating, and note any version this client has to stay on.
```
$md$),
('00000000-0000-4000-8004-000000000006', 'Backup and recovery', '00000000-0000-4000-8003-000000000005',
 'What is backed up, where, how to restore, and the restore tests.', $md$# Backup and recovery: {{client.name}}

| What | Product | Schedule | Retention | Destination |
|---|---|---|---|---|
| Servers | | Nightly | 30 days | |
| Microsoft 365 | | Daily | 1 year | |
| | | | | |

```fields
Backup console:
Offsite copy:
Alerts go to:
```

```credential
label: Backup console
```

```credential
label: Backup encryption key
```

```callout danger
Without the encryption key the backups can't be restored. Keep a copy outside this system too.
```

## Restoring

1. Confirm what has to come back, and from when.
2. Restore to a separate location first if the original might still be in use.
3. Check with the user before replacing anything.

## Restore tests

| Date | What was restored | By | Result |
|---|---|---|---|
| {{date}} | | {{user.name}} | |
$md$),
('00000000-0000-4000-8004-000000000007', 'Vendor', '00000000-0000-4000-8003-000000000006',
 'A supplier: account, support contacts, portal and escalation.', $md$# Vendor name

```fields
Supplies:
Account number:
Support phone:
Support email:
Support hours:
Contract ends:
Account manager:
```

```credential
label: Vendor portal
```

## Raising a case

What they ask for (account number, serial numbers, the authorised contact) and how long they usually take.

## Escalation

| Level | Name | Phone | Email |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
$md$),
('00000000-0000-4000-8004-000000000008', 'New user procedure', '00000000-0000-4000-8003-000000000007',
 'The steps for a new starter at this client.', $md$# New user procedure: {{client.name}}

```callout info
Ask for: full name, job title, department, manager, start date, and the systems they need.
```

## Accounts

- [ ] Create the account (naming: firstname.lastname)
- [ ] Assign licences
- [ ] Add to the department's groups and shared mailboxes
- [ ] Line-of-business applications

## Equipment

- [ ] Laptop or desktop with the agent installed and updates done
- [ ] Printers and mapped drives
- [ ] Phone extension

## First day

- [ ] Sign in with them and set up MFA
- [ ] Building access
- [ ] Send the welcome email: how to reach the help desk
$md$),
('00000000-0000-4000-8004-000000000009', 'Client onboarding checklist', '00000000-0000-4000-8003-000000000008',
 'Everything to collect and set up when a new client signs.', $md$# Onboarding: {{client.name}}

Started {{date}} by {{user.name}}.

## Discovery

- [ ] Contacts, including who may approve work and spending
- [ ] Sites, opening hours and how to get in
- [ ] Network documented (*Network overview* template)
- [ ] Servers and line-of-business applications documented
- [ ] Vendors collected: internet, phones, printers, software

## Access

- [ ] Admin credentials moved into the vault
- [ ] The previous provider's access removed
- [ ] Microsoft 365 or Google Workspace admin access

## Tools

- [ ] Agent on every workstation and server
- [ ] Patch policy and maintenance window
- [ ] Monitoring and alerts checked
- [ ] Backups verified with a test restore
- [ ] Security sensor on

## Handover

- [ ] Client shown how to raise tickets (portal, email, phone)
- [ ] Contract and billing set up
- [ ] First review booked
$md$);

-- ---------------------------------------------------------------------------
-- The vault. A random key per client, wrapped with RMM_DATA_KEY, seals the password, notes and
-- TOTP secret of each item (associated data "<item id>:<column>"). Name, username and URL are
-- in the clear: lists and search need them.
-- ---------------------------------------------------------------------------
CREATE TABLE vault_keys (
    client_id    uuid PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    wrapped_key  bytea NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE vault_items (
    id                   uuid PRIMARY KEY,
    client_id            uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name                 text NOT NULL,
    username             text NOT NULL DEFAULT '',
    url                  text NOT NULL DEFAULT '',
    password             bytea,
    notes                bytea,
    totp_secret          bytea,
    totp_algorithm       text NOT NULL DEFAULT 'SHA1' CHECK (totp_algorithm IN ('SHA1', 'SHA256', 'SHA512')),
    totp_digits          smallint NOT NULL DEFAULT 6 CHECK (totp_digits BETWEEN 6 AND 8),
    totp_period          smallint NOT NULL DEFAULT 30 CHECK (totp_period BETWEEN 1 AND 300),
    password_changed_at  timestamptz,
    created_by           uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_by           uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON vault_items (client_id, lower(name));

-- Earlier passwords (the last 10), still sealed for "<item id>:password".
CREATE TABLE vault_item_history (
    id           bigserial PRIMARY KEY,
    item_id      uuid NOT NULL REFERENCES vault_items(id) ON DELETE CASCADE,
    password     bytea NOT NULL,
    replaced_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    replaced_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON vault_item_history (item_id, id DESC);

-- Derived from the `vault:<id>` references in a document's body on every save.
CREATE TABLE client_doc_vault_links (
    doc_id   uuid NOT NULL REFERENCES client_docs(id) ON DELETE CASCADE,
    item_id  uuid NOT NULL REFERENCES vault_items(id) ON DELETE CASCADE,
    PRIMARY KEY (doc_id, item_id)
);
CREATE INDEX ON client_doc_vault_links (item_id);
