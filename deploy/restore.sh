#!/bin/sh
# Restores a backup made by backup.sh: the database and the local object storage. Used by the
# `restore` service of the compose stacks and by the CI restore drill (scripts/restore-drill.sh).
#
#   restore.sh <name | latest>      e.g. rmm-20260101T030000Z
#
# STOP THE SERVER FIRST. Then, for the compose stacks, from the repository root:
#   docker compose -f deploy/docker-compose.yml stop server
#   docker compose -f deploy/docker-compose.yml --profile restore run --rm restore rmm-20260101T030000Z
#   docker compose -f deploy/docker-compose.yml start server
#
# Settings: the PG* connection (PGHOST PGUSER PGPASSWORD PGDATABASE), BACKUP_DIR (default
# /backups) and STORAGE_DIR (default /srv/data/storage).
#  - The database is replaced: tables are dropped and recreated from the dump, all in one
#    transaction, so a failed restore leaves the old data. The target should be the empty database
#    of a fresh stack, or the one you mean to overwrite.
#  - The storage directory must be empty, or RESTORE_REPLACE_STORAGE=1 empties it first.
#    A backup without a files tarball (S3 storage) leaves it alone.
# Start the server with the RMM_DATA_KEY the backup was taken under: 2FA secrets, mailbox and
# accounting credentials, detection context and the vault are sealed with it.
set -eu
dir=${BACKUP_DIR:-/backups}
storage=${STORAGE_DIR:-/srv/data/storage}
name=${1:-}
[ -n "$name" ] || { echo "usage: restore.sh <rmm-YYYYMMDDTHHMMSSZ | latest>" >&2; exit 2; }
if [ "$name" = latest ]; then
    newest=$(ls -1 "$dir"/rmm-*.dump 2>/dev/null | sort | tail -n 1)
    [ -n "$newest" ] || { echo "restore: no rmm-*.dump in $dir" >&2; exit 1; }
    name=$(basename "$newest" .dump)
fi
name=${name%.dump}
dump="$dir/$name.dump"
files="$dir/$name.files.tar.gz"
[ -f "$dump" ] || { echo "restore: $dump not found" >&2; exit 1; }

if [ -f "$files" ]; then
    mkdir -p "$storage"
    if [ -n "$(ls -A "$storage")" ]; then
        [ "${RESTORE_REPLACE_STORAGE:-}" = 1 ] || { echo "restore: $storage isn't empty; empty it, or set RESTORE_REPLACE_STORAGE=1 to have it emptied first" >&2; exit 1; }
    fi
    # Checked before anything is touched.
    tar -tzf "$files" > /dev/null || { echo "restore: $files is damaged" >&2; exit 1; }
fi

echo "restore: database from $dump"
pg_restore --single-transaction --clean --if-exists --no-owner --exit-on-error -d "$PGDATABASE" "$dump"

if [ -f "$files" ]; then
    echo "restore: storage from $files into $storage"
    find "$storage" -mindepth 1 -delete
    tar -C "$storage" -xzf "$files"
else
    echo "restore: no $files: storage left as it is"
fi
echo "restore: done; start the server with the RMM_DATA_KEY of the backup"
