#!/usr/bin/env bash
# Restore drill: proves that a backup made the way the compose stacks make it restores into a
# server that works. A backup nobody has restored is a hope, not a backup. Used by the CI job
# `restore-drill`; runs the same way locally:
#
#   docker run -d --rm --name pg-drill -e POSTGRES_PASSWORD=pg -p 54320:5432 postgres:17-alpine
#   cargo build -p rmm-agent -p rmm-server
#   RMM_E2E_DATABASE_URL=postgres://postgres:pg@localhost:54320/postgres scripts/restore-drill.sh
#
# 1. checks that the copies of deploy/backup.sh and deploy/restore.sh pasted into the Arcane
#    stack are identical, and that both compose files parse;
# 2. runs the e2e suite (tests/e2e.rs) with RMM_E2E_DRILL and RMM_E2E_KEEP, which leaves its
#    database and storage directory behind and writes down what must come back;
# 3. backs them up with deploy/backup.sh (in the postgres image, as the compose `backup` service
#    does): a dump and a storage tarball;
# 4. restores them with deploy/restore.sh into a brand new database and an empty directory, and
#    checks the guard rails (a second restore into the filled directory is refused, and works with
#    RESTORE_REPLACE_STORAGE=1, over the filled database);
# 5. starts rmm-server on the restored copies and reads the e2e's rows back, an attachment's
#    bytes among them (tests/drill.rs).
#
# Needs Docker (the postgres image's pg_dump matches the server), cargo, and jq. The Postgres
# in RMM_E2E_DATABASE_URL must be reachable from the host network (Docker --network host).
set -euo pipefail
cd "$(dirname "$0")/.."

: "${RMM_E2E_DATABASE_URL:?set RMM_E2E_DATABASE_URL to a Postgres you can CREATE DATABASE on (see the script header)}"
PG_IMAGE=${PG_IMAGE:-postgres:17-alpine}
re='^postgres(ql)?://([^:@/]+)(:([^@/]*))?@([^:/]+)(:([0-9]+))?/'
[[ $RMM_E2E_DATABASE_URL =~ $re ]] || { echo "can't parse RMM_E2E_DATABASE_URL" >&2; exit 2; }
pg_user=${BASH_REMATCH[2]} pg_pass=${BASH_REMATCH[4]} pg_host=${BASH_REMATCH[5]} pg_port=${BASH_REMATCH[7]:-5432}
base_url=${RMM_E2E_DATABASE_URL%/*}
work=$(mktemp -d "${TMPDIR:-/tmp}/rmm-drill.XXXXXX")
restored_db=rmm_drill_restored_$$
src_db=""
cleanup() {
  status=$?
  if [ -n "$src_db" ]; then pgdocker psql -qc "DROP DATABASE IF EXISTS $src_db WITH (FORCE)" -d postgres >/dev/null 2>&1 || true; fi
  pgdocker psql -qc "DROP DATABASE IF EXISTS $restored_db WITH (FORCE)" -d postgres >/dev/null 2>&1 || true
  if [ $status -eq 0 ]; then rm -rf "$work" "${kept_dir:-}"; else echo "drill failed; working files kept in $work (and ${kept_dir:-})" >&2; fi
}
trap cleanup EXIT

# Runs a postgres-image tool against the e2e Postgres, as the invoking user so the files it
# writes are ours.
pgdocker() {
  docker run --rm --network host --user "$(id -u):$(id -g)" \
    -e PGHOST="$pg_host" -e PGPORT="$pg_port" -e PGUSER="$pg_user" -e PGPASSWORD="$pg_pass" \
    "${DOCKER_ARGS[@]}" "$PG_IMAGE" "$@"
}
DOCKER_ARGS=()

echo "== 1. deploy files"
# The Arcane stack carries copies of the scripts as inline configs ($ doubled for Compose).
for f in backup.sh restore.sh; do
  awk -v name="  $f:" '
    $0 == name { found = 1; next }
    found && /^    content: \|$/ { body = 1; next }
    body { if (/^      /) { sub(/^      /, ""); gsub(/\$\$/, "$"); while (blank > 0) { print ""; blank-- } print } else if (/^$/) blank++; else exit }
  ' deploy/arcane/compose.yaml > "$work/arcane-$f"
  diff -u "deploy/$f" "$work/arcane-$f" || { echo "deploy/arcane/compose.yaml has a different copy of $f: update the inline config" >&2; exit 1; }
done
if docker compose version >/dev/null 2>&1; then
  export POSTGRES_PASSWORD=x RMM_DOMAIN=x RMM_PUBLIC_URL=http://x RMM_DATA_KEY=x
  docker compose -f deploy/docker-compose.yml --profile restore config -q
  docker compose -f deploy/arcane/compose.yaml --profile restore config -q
fi
sh -n deploy/backup.sh && sh -n deploy/restore.sh

echo "== 2. e2e run, keeping its database and storage"
RMM_E2E_DRILL="$work/expect.json" RMM_E2E_KEEP=1 cargo test -p rmm-server --test e2e end_to_end -- --ignored --nocapture 2>&1 | tee "$work/e2e.log" | grep -E '^(test |RMM_E2E_KEPT|restore drill)|panicked|FAILED' || true
kept=$(grep -E '^RMM_E2E_KEPT ' "$work/e2e.log" | tail -n 1) || { echo "the e2e run failed (see above)" >&2; tail -n 40 "$work/e2e.log"; exit 1; }
src_db=$(sed -E 's/.*database=([^ ]+).*/\1/' <<<"$kept")
kept_dir=$(sed -E 's/.* dir=(.*)$/\1/' <<<"$kept")
test -s "$work/expect.json" && test -d "$kept_dir/storage"
echo "source: database $src_db, storage $kept_dir/storage ($(du -sh "$kept_dir/storage" | cut -f1))"

echo "== 3. backup, with the compose stack's backup.sh"
mkdir -p "$work/backups"
DOCKER_ARGS=(-e PGDATABASE="$src_db" -e BACKUP_DIR=/backups -v "$work/backups:/backups"
  -v "$kept_dir/storage:/srv/data/storage:ro" -v "$PWD/deploy/backup.sh:/backup.sh:ro")
pgdocker sh /backup.sh
dump=$(ls "$work"/backups/rmm-*.dump); files=$(ls "$work"/backups/rmm-*.files.tar.gz)
test -s "$dump" && test -s "$files"
tar -tzf "$files" | grep -q '^\./attachments/' || { echo "the storage backup has no attachments/" >&2; exit 1; }
name=$(basename "$dump" .dump)
echo "backup: $name ($(du -h "$dump" | cut -f1) dump, $(du -h "$files" | cut -f1) files)"

echo "== 4. restore into a new database and an empty directory, with restore.sh"
DOCKER_ARGS=()
pgdocker createdb "$restored_db"
mkdir -p "$work/restored-storage"
restore() {
  DOCKER_ARGS=(-e PGDATABASE="$restored_db" -e BACKUP_DIR=/backups -e STORAGE_DIR=/restored -e RESTORE_REPLACE_STORAGE="${RESTORE_REPLACE_STORAGE:-}"
    -v "$work/backups:/backups:ro" -v "$work/restored-storage:/restored" -v "$PWD/deploy/restore.sh:/restore.sh:ro")
  pgdocker sh /restore.sh "$@"
}
restore "$name"
if restore latest >/dev/null 2>"$work/refused.log"; then echo "a restore into a filled storage directory must be refused" >&2; exit 1; fi
grep -q "isn't empty" "$work/refused.log"
RESTORE_REPLACE_STORAGE=1 restore latest   # also over the already restored database
test "$(find "$work/restored-storage" -type f | wc -l)" -eq "$(find "$kept_dir/storage" -type f -not -name '*.partial' | wc -l)"

echo "== 5. a server on the restored copies"
RMM_DRILL_DATABASE_URL="$base_url/$restored_db" RMM_DRILL_STORAGE="$work/restored-storage" RMM_DRILL_EXPECT="$work/expect.json" \
  cargo test -p rmm-server --test drill -- --ignored --nocapture
echo "restore drill: ok"
