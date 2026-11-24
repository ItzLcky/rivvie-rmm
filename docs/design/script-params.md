# Script parameters and variables

Design record, 2026-11-24 (parity plan A1). Migration `0036_script_params.sql`; server in `crates/rmm-server/src/params.rs`, `api/{scripts,jobs}.rs`, `policy.rs`, `scheduler.rs`, `automation.rs`, `alerts.rs`; agent in `crates/rmm-agent/src/jobs.rs`; web in `web/src/lib/components/scripts/{ParamsEditor,ParamInputs}.svelte`.

## Decision: environment variables

A saved script declares typed parameters. A run gives them values, and each reaches the script as the environment variable `RMM_PARAM_<NAME>` on the child process. The script body and its arguments are never rewritten, so a value can't become code for any of the five interpreters (templating into text is command injection, `cmd.exe /C` re-parses argv). Read them as `$RMM_PARAM_X` (sh, bash), `$env:RMM_PARAM_X` (PowerShell), `%RMM_PARAM_X%` (cmd), `os.environ["RMM_PARAM_X"]` (Python).

Every job also gets `RMM_AGENT_ID`, `RMM_AGENT_HOSTNAME`, `RMM_AGENT_OS` (the OS family), `RMM_AGENT_PLATFORM`, `RMM_CLIENT_ID`, `RMM_CLIENT_NAME`, `RMM_SITE_ID`, `RMM_SITE_NAME` and `RMM_JOB_ID`, ad-hoc scripts included.

## Declaring

`scripts.params` is `[{name, label, type, required, default, choices, description}]`:

- `name`: `[a-z][a-z0-9_]{0,39}`, unique; at most 30 parameters.
- `type`: `text`, `number`, `bool`, `select` (1-50 distinct `choices`) or `secret`.
- `default`: coerced to the type when saved; never for a secret (it would be stored in the clear).
- Values are checked as custom fields are (`fields::coerce`): strings are accepted for every type (`"42"`, `"yes"`), a select matches its choices ignoring case.

`PUT /scripts/{id}` without `params` leaves them unchanged. Changing them re-validates every schedule, automation and alert policy that runs the script (in every set it reaches) and answers 409 naming the policy if one no longer fits.

## Values and placeholders

- Run dialog / `POST /jobs`: `params: {name: value}` (saved scripts only; ad-hoc scripts take none).
- Schedule and automation items: `config.params: {name: "value"}` (strings), overridable per key in descendant sets (the config merge is key by key, so an override changes one value).
- Alert scripts (`run_script_id`) pass no values: a script with a required parameter without a default can't be chosen there.

A `text` value may hold `{{agent.hostname}}`, `{{agent.id}}`, `{{agent.os}}`, `{{client.name}}`, `{{site.name}}` or `{{field.<name>}}` (inner spaces allowed). The server expands them per device before the job exists; a custom field is read from the agent, then its site, then its client, and only the fields referenced are read. An unknown placeholder, or a field name no custom field has, is a 400 when saved. Expanded text is inserted as is, never re-scanned. Placeholders in other types are refused. **Choice made here:** placeholders only in `text` values (a number from a field would need a second coercion per device).

Limits: 8 KiB per value after expansion, 20 KiB for all of a job's values, 20 distinct fields per value set. The agent checks again: names must match `RMM_[A-Z0-9_]+` (so nothing can set `PATH` or `LD_PRELOAD`), 8 KiB per value, 24 KiB in all.

## Secrets

- A `secret` value is shown as `•••` in `jobs.params`, the job page and the audit log (`job.create` lists names and non-secret values).
- Its value waits in `jobs.env_sealed`: `{name: value}` JSON sealed with `RMM_DATA_KEY`, associated data `job-env:<job id>`. A trigger (`jobs_drop_env`) drops it as soon as the job's status is anything but `queued`/`sent`, whatever code moved it. `rotate::TABLES` lists it (`flag: None`, prefix `job-env:`).
- Secrets need `RMM_DATA_KEY` (409 without it).
- Policies never store a secret: the value must be `vault:<item id>`, read at launch from the device's client vault. The item must be limited to that client (checked on every write, merged configs included). Writing such a policy needs `vault.read` and 2FA, and not an API key. Each launch that reads a vault item writes `vault.use` (item, job, via).
- In the run dialog a secret is typed in, or picked from the vault when every selected device is one client's. `POST /jobs` with `vault:<id>` limits the run to that item's client's agents; API keys can't name vault items (the vault isn't in the public API).
- Environment variables are readable by same-user processes and children. Scripts run as root/SYSTEM, so this is accepted. Job output is stored: don't echo secrets (redaction is not attempted, see the parity plan's cuts).

## Delivery and compatibility

`params::job_env` builds the environment when a job is sent (at once, or from `dispatch_queued` on reconnect), from `jobs.params`, the opened secrets and the agent's current names. `ScriptJob.env` is `#[serde(default)]`: an old server sends none and an old agent ignores it. Agents announce the `script_env` capability; a job with parameters for an agent without it ends `error` ("agent too old for script parameters") instead of running without them. The capabilities are stored at connect before queued jobs are dispatched.

## Tests

Unit: spec validation, coercion and defaults, placeholder parsing and expansion, env names, sealing per job, the proto round trip both ways, the agent's env checks and a real `sh` run of a hostile value. e2e `script_params` (`RMM_E2E_ONLY=script_params`): a bash script prints its environment; `$(touch X); "` arrives verbatim and X doesn't exist; the secret is in no `jobs` column but the output and in no audit entry; refused values; `{{field.x}}` per device; a vault item value and its `vault.use`; an offline agent gets the secret after reconnecting and `env_sealed` is then NULL; an agent without the capability gets `error`; a schedule override changes one value; a stricter script answers 409 naming the schedule. `key_rotation` rewraps a queued job's `env_sealed` and the agent runs it on the new key. Windows (`$env:` and `%…%`) is in `docs/design/windows-testing.md`.
