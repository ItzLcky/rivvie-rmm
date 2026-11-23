#!/bin/sh
# One backup of everything the server keeps: a pg_dump of the database and, beside it, a
# tarball of the local object storage (ticket attachments, raw inbound email, invoice PDFs,
# triage packages), then pruning of backups older than BACKUP_KEEP_DAYS.
#
# Used by the `backup` service of both compose stacks and by the CI restore drill
# (scripts/restore-drill.sh), so what CI restores is what production writes. Runs in the
# postgres image (pg_dump, busybox tar). Settings, all optional but the PG* connection:
#   PGHOST PGUSER PGPASSWORD PGDATABASE   where the database is
#   BACKUP_DIR        where backups go (default /backups)
#   STORAGE_DIR       the server's RMM_STORAGE_DIR as mounted here (default /srv/data/storage);
#                     skipped if it isn't a directory (RMM_S3_BUCKET set: back the bucket up instead)
#   BACKUP_KEEP_DAYS  default 14
#
# The two files share a timestamp: rmm-<ts>.dump and rmm-<ts>.files.tar.gz.
# The dump goes first. A file uploaded in between is in the tarball without a database row
# (harmless); the other order could leave a row whose file isn't in the tarball.
# Exits non-zero if either part failed (the other is kept, and pruning still runs).
set -u
umask 077
dir=${BACKUP_DIR:-/backups}
storage=${STORAGE_DIR:-/srv/data/storage}
keep=${BACKUP_KEEP_DAYS:-14}
ts=$(date -u +%Y%m%dT%H%M%SZ)
status=0

dump="$dir/rmm-$ts.dump"
if pg_dump -Fc -f "$dump.part"; then
    mv "$dump.part" "$dump" && echo "backup: wrote $dump ($(du -h "$dump" | cut -f1))"
else
    rm -f "$dump.part"; echo "backup: pg_dump failed" >&2; status=1
fi

if [ -d "$storage" ]; then
    files="$dir/rmm-$ts.files.tar.gz"
    # *.partial are uploads in flight (written beside the final name, then renamed).
    if tar -C "$storage" --exclude='*.partial' -czf "$files.part" . ; then
        mv "$files.part" "$files" && echo "backup: wrote $files ($(du -h "$files" | cut -f1))"
    else
        rm -f "$files.part"; echo "backup: archiving $storage failed" >&2; status=1
    fi
else
    echo "backup: $storage isn't a directory: no local storage to archive (back up your S3 bucket separately)"
fi

find "$dir" \( -name 'rmm-*.dump' -o -name 'rmm-*.files.tar.gz' \) -mtime +"$keep" -delete
exit $status
