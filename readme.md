## 项目依赖
- go 1.26.0
- postgres 
- redis 

### redis 
redis-cli 
INFO keyspace  
SELECT 10 
LRANGE sast:scan:queue 0 -1 

### postgres
client-cli:
\d
\c
\dt
\l

init db sql
```sql
CREATE TABLE sast_findings (id BIGSERIAL PRIMARY KEY, scan_id BIGINT NOT NULL REFERENCES sast_scans(id) ON DELETE CASCADE, ordinal INTEGER NOT NULL, rule_id TEXT NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL DEFAULT '', level TEXT NOT NULL DEFAULT 'warning', security_score DOUBLE PRECISION CHECK (security_score IS NULL OR security_score BETWEEN 0 AND 10), cwes JSONB NOT NULL DEFAULT '[]'::jsonb, locations JSONB NOT NULL DEFAULT '[]'::jsonb, related_locations JSONB NOT NULL DEFAULT '[]'::jsonb, code_flows JSONB NOT NULL DEFAULT '[]'::jsonb, fingerprints JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (scan_id, ordinal)); CREATE INDEX idx_sast_findings_scan_id_id ON sast_findings(scan_id, id);
```
