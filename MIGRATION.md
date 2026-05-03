# Schema v2 Migration Runbook

Cutover from v1 (text-typed, no partitioning) to v2 (uuid/inet/smallint, daily partitions). User authorized **TRUNCATE** of existing analytics data — no historical migration. Agents resume immediately and rebuild data going forward.

## Pre-flight (day before)

1. **Confirm VM 101 disk free ≥ 20 GB** (we backup pre-cut volume; needs headroom):
   ```bash
   ssh dedik "ssh root@10.10.10.20 'df -h /'"
   ```

2. **Snapshot index usage stats** (for post-migration cleanup of unused indexes):
   ```bash
   ssh dedik "ssh root@10.10.10.20 \"docker exec analyzer-postgres psql -U xray_analyzer -d xray_analyzer -c '\\\\copy (SELECT * FROM pg_stat_user_indexes) TO STDOUT WITH CSV HEADER'\"" \
     > /tmp/pre-migration-index-stats.csv
   ```
   Keep this file locally; review after 7 days post-cutover.

3. **Notify** in chat: `analyzer brief downtime ~5 min for schema upgrade in 30 min`.

## Backup snapshot (emergency rollback safety net)

```bash
ssh dedik "ssh root@10.10.10.20 'mkdir -p /opt/xray/log-analyzer/backups && \
  docker run --rm \
    -v log-analyzer_analyzer-postgres-data:/d \
    -v /opt/xray/log-analyzer/backups:/backup \
    alpine tar czf /backup/pg-pre-v2-\$(date +%Y%m%d-%H%M).tgz /d'"
```

Verify the file exists before proceeding:
```bash
ssh dedik "ssh root@10.10.10.20 'ls -lh /opt/xray/log-analyzer/backups/'"
```

## Cutover (~5 min)

```bash
ssh dedik "ssh root@10.10.10.20 'cd /opt/xray/log-analyzer && \
  docker compose stop xray-log-analyzer && \
  docker compose stop analyzer-postgres && \
  docker volume rm log-analyzer_analyzer-postgres-data && \
  git fetch origin && git checkout refactor/schema-v2 && \
  docker compose build analyzer-server && \
  docker compose up -d analyzer-postgres analyzer-redis xray-log-analyzer'"
```

Watch logs for 1-2 minutes:
```bash
ssh dedik "ssh root@10.10.10.20 'docker logs -f xray-log-analyzer 2>&1 | head -50'"
```
Exit with Ctrl+C once you see `partition manager: started` and the threat alert flow resumes.

## Verify (10 min after up)

1. **Container health:**
   ```bash
   ssh dedik "ssh root@10.10.10.20 'docker ps --filter name=xray-log-analyzer --format \"{{.Status}}\"'"
   ```
   Expect: `Up X seconds (healthy)`.

2. **Stats endpoint** (uses /api/stats, requires API_TOKEN — pull from `/opt/xray/log-analyzer/.env`):
   ```bash
   ssh dedik "ssh root@10.10.10.20 'source /opt/xray/log-analyzer/.env && \
     curl -sS -H \"Authorization: Bearer \$API_TOKEN\" http://localhost:8237/api/stats'"
   ```
   Expect: `nodes_connected: 8` or `9`.

3. **Today/tomorrow/+2 partitions exist:**
   ```bash
   ssh dedik "ssh root@10.10.10.20 \"docker exec analyzer-postgres psql -U xray_analyzer -d xray_analyzer -c \\\"SELECT relname FROM pg_class WHERE relname LIKE 'bridged_flows_%' ORDER BY 1\\\"\""
   ```
   Expect: `bridged_flows_default`, `bridged_flows_<today>`, `<tomorrow>`, `<+2>`.

4. **Threats writing:**
   ```bash
   ssh dedik "ssh root@10.10.10.20 'docker logs --since 2m xray-log-analyzer 2>&1 | grep \"threat alert\" | tail -5'"
   ```

5. **Disk check** (should be much smaller right after cutover):
   ```bash
   ssh dedik "ssh root@10.10.10.20 'df -h / && du -sh /var/lib/docker/volumes/log-analyzer_analyzer-postgres-data'"
   ```

## Rollback A — code regression, schema OK

If new code has a bug but the database is fine:

```bash
ssh dedik "ssh root@10.10.10.20 'cd /opt/xray/log-analyzer && \
  git checkout postgres-migration && \
  docker compose build analyzer-server && \
  docker compose up -d analyzer-server'"
```

Note: this leaves the v2 schema in place. The v1 code expects v1 schema, so rollback A only works if the code regression is unrelated to schema changes. For schema-related rollback, use B.

## Rollback B — schema disaster, restore from backup

```bash
ssh dedik "ssh root@10.10.10.20 'cd /opt/xray/log-analyzer && \
  docker compose down && \
  docker volume rm log-analyzer_analyzer-postgres-data && \
  docker run --rm \
    -v log-analyzer_analyzer-postgres-data:/d \
    -v /opt/xray/log-analyzer/backups:/b \
    alpine sh -c \"cd /d && tar xzf /b/pg-pre-v2-*.tgz --strip-components 1\" && \
  git checkout postgres-migration && \
  docker compose build analyzer-server && \
  docker compose up -d'"
```

Verify nodes_connected returns to expected count.

## Post-deploy (week 1 monitoring)

| Day | Check | Command |
|---|---|---|
| 1 | Disk plateau started? | `df -h /` should be growing slowly (~2GB/day at most) |
| 1 | Partition manager creating tomorrow's? | logs grep `partition` |
| 7 | bridged_flows older than 14d gone? | `SELECT relname FROM pg_class WHERE relname LIKE 'bridged_flows_%' ORDER BY 1` — oldest should be ~14 days back |
| 7 | iowait improved? | `top` on VM, %wa column ≤ 5% |
| 7 | Memory: postgres / analyzer | `docker stats --no-stream` |
| 14 | Disk plateau confirmed? | `df -h /` should plateau between 12-17 GB postgres volume |
| 14 | pg_stat_statements regressions? | Compare hot queries vs pre-migration baseline |

After 7 days of stable operation:
```bash
# Drop emergency backup snapshot
ssh dedik "ssh root@10.10.10.20 'rm /opt/xray/log-analyzer/backups/pg-pre-v2-*.tgz'"
```

## Troubleshooting

**"missing partition X for today" in /health response:**
- Partition manager goroutine died or DB was unreachable.
- Manual fix:
  ```sql
  CREATE TABLE bridged_flows_<YYYYMMDD> PARTITION OF bridged_flows
  FOR VALUES FROM ('YYYY-MM-DD 00:00:00+00') TO ('YYYY-MM-DD+1 00:00:00+00');
  ```
- Restart container: `docker compose restart xray-log-analyzer`.

**`bridged_flows_default` non-empty:**
- Healthcheck warns if DEFAULT has rows — partition manager missed a window. Means data went to default but is still queryable. Manual partition creation + INSERT-SELECT migration:
  ```sql
  -- Create the day's partition first
  CREATE TABLE bridged_flows_<YYYYMMDD> PARTITION OF bridged_flows ...
  -- Move from default
  WITH moved AS (DELETE FROM bridged_flows_default WHERE ts >= 'YYYY-MM-DD' AND ts < 'YYYY-MM-DD+1' RETURNING *)
  INSERT INTO bridged_flows_<YYYYMMDD> SELECT * FROM moved;
  ```

**Agents reconnect but no INSERTs landing:**
- Check FK constraints — agents may report `node_id` text values that don't yet exist in `nodes` lookup. The storage layer auto-inserts via `LookupNodeID`, but if it's failing check logs for `lookup node` errors.

**Postgres won't start with new tuning:**
- `shared_buffers=2GB` requires postgres to have access to ≥2GB shared memory. Most kernels set this fine, but if you see "could not map anonymous shared memory" check `sysctl kernel.shmmax` on the VM.
- Fallback: edit `docker-compose.yml`, drop `shared_buffers=2GB` to `shared_buffers=512MB`, restart. Then investigate.
