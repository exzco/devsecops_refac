package dashboard

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Summary struct {
	Repos int64 `json:"repos"`
	Scans int64 `json:"scans"`
	Findings int64 `json:"findings"`
	Batches int64 `json:"batches"`
	Ports int64 `json:"ports"`
	Vulnerabilities int64 `json:"vulnerabilities"`
}

type store struct {
	db *pgxpool.Pool
}

func (s *store) summary(ctx context.Context, user string) (Summary, error) {
	var result Summary
	err := s.db.QueryRow(ctx, `WITH mine AS (
		SELECT id FROM dast_scans WHERE created_by=$1
	), tasks AS (
		SELECT t.id,t.result,t.plan->'asset' AS asset FROM dast_tasks t JOIN mine ON mine.id=t.scan_id
	) SELECT count(DISTINCT NULLIF(repo_url,'')), count(*), (SELECT count(*) FROM sast_findings),
		(SELECT count(*) FROM mine), (SELECT count(DISTINCT (asset->>'cluster_id',asset->>'network_zone',endpoint))
			FROM tasks CROSS JOIN LATERAL jsonb_path_query(result,'$.ports[*] ? (@.state == "open").endpoint') AS p(endpoint)),
		(SELECT count(*) FROM dast_findings f JOIN tasks ON tasks.id=f.task_id) FROM sast_scans`, user).
		Scan(&result.Repos, &result.Scans, &result.Findings, &result.Batches, &result.Ports, &result.Vulnerabilities)
	return result, err
}
