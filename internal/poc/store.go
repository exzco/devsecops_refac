package poc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Service) invalidate(ctx context.Context, id string) {
	if s.redis != nil && id != "" {
		_ = s.redis.Del(ctx, "poc:cve:"+id).Err()
	}
}

func (s *Service) list(ctx context.Context, f CVEFilter) ([]CVE, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	clauses := []string{}
	args := []any{}
	argIdx := 1

	if f.Query != "" {
		clauses = append(clauses, fmt.Sprintf("(id ILIKE $%d OR manual->>'title' ILIKE $%d OR manual->>'description' ILIKE $%d)", argIdx, argIdx, argIdx))
		args = append(args, "%"+f.Query+"%")
		argIdx++
	}

	if f.Year == "2018-2026" {
		clauses = append(clauses, "substring(id from 5 for 4) BETWEEN '2018' AND '2026'")
	} else if f.Year != "" && f.Year != "all" {
		clauses = append(clauses, fmt.Sprintf("id LIKE $%d", argIdx))
		args = append(args, "CVE-"+f.Year+"-%")
		argIdx++
	}

	hasGitHub := `(sources ?| ARRAY['CVEProject/cvelistV5','nomi-sec/PoC-in-GitHub','trickest/cve']
		OR EXISTS (SELECT 1 FROM jsonb_object_keys(sources) AS source(name) WHERE name LIKE 'github:%')
		OR jsonb_array_length(COALESCE(sources->'projectdiscovery/nuclei-templates'->'links','[]'::jsonb)) > 0
		OR EXISTS (SELECT 1 FROM jsonb_array_elements(discovered) AS link WHERE link->>'url' ~* '^https?://github[.]com/'))`
	sources := map[string]string{
		"github":             hasGitHub,
		"nvd":                "sources ? 'nvd'",
		"github-without-nvd": hasGitHub + " AND NOT (sources ? 'nvd')",
	}
	if f.Source != "" {
		clause, ok := sources[f.Source]
		if !ok {
			return nil, errors.New("未知来源条件")
		}
		clauses = append(clauses, clause)
	}

	if f.Start != "" {
		clauses = append(clauses, fmt.Sprintf("updated_at >= $%d::timestamptz", argIdx))
		args = append(args, f.Start)
		argIdx++
	}
	if f.End != "" {
		clauses = append(clauses, fmt.Sprintf("updated_at <= $%d::timestamptz", argIdx))
		args = append(args, f.End+" 23:59:59")
		argIdx++
	}

	query := "SELECT id,sources #- '{projectdiscovery/nuclei-templates,templates}',discovered,manual,searched_at,updated_at FROM poc_cves"
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY CASE WHEN id ~ '^CVE-[0-9]{4}-[0-9]+$' THEN split_part(id, '-', 2)::int ELSE 0 END DESC, CASE WHEN id ~ '^CVE-[0-9]{4}-[0-9]+$' THEN split_part(id, '-', 3)::bigint ELSE 0 END DESC, updated_at DESC LIMIT %d", limit)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []CVE{}
	for rows.Next() {
		var c CVE
		if err := rows.Scan(&c.ID, &c.Sources, &c.Discovered, &c.Manual, &c.SearchedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		if err := c.MergeLinks(); err != nil {
			return nil, err
		}
		items = append(items, c)
	}
	return items, rows.Err()
}

func (s *Service) get(ctx context.Context, id string) (CVE, error) {
	var c CVE
	err := s.db.QueryRow(ctx, `SELECT id,sources,discovered,manual,searched_at,updated_at FROM poc_cves WHERE id=$1`, id).Scan(&c.ID, &c.Sources, &c.Discovered, &c.Manual, &c.SearchedAt, &c.UpdatedAt)
	if err == nil {
		err = c.MergeLinks()
	}
	return c, err
}

func (s *Service) ingest(ctx context.Context, id, source string, record any) error {
	if !ValidCVE(id) {
		return fmt.Errorf("invalid CVE ID: %s", id)
	}
	_, err := s.db.Exec(ctx, `INSERT INTO poc_cves(id,sources) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET sources=poc_cves.sources || EXCLUDED.sources,updated_at=now()`, id, map[string]any{source: record})
	if err == nil {
		s.invalidate(ctx, id)
	}
	return err
}

// Decode old records at the storage boundary without rewriting their saved payloads.
func readGenerationSpec(raw json.RawMessage, oldTemplate string) (Spec, error) {
	var spec Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return spec, err
	}
	if spec.Version != 0 {
		return spec, nil
	}
	var old struct {
		Status    string `json:"status"`
		CheckType string `json:"check_type"`
		Reason    string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		return spec, err
	}
	kind := old.CheckType
	if kind == "" {
		kind = "legacy"
	}
	result := PoCResult{Kind: kind, Status: old.Status, Reason: old.Reason, MissingInformation: []string{}, Template: json.RawMessage("null")}
	if old.Status == "needs-evidence" {
		result.MissingInformation = []string{old.Reason}
	}
	if oldTemplate != "" {
		result.Template = json.RawMessage(oldTemplate)
	}
	spec.Version = 1
	spec.Results = []PoCResult{result}
	return spec, nil
}

func (s *Service) saveGeneration(ctx context.Context, id string, spec Spec, generationID int64) (int64, error) {
	if _, err := Render(id, spec); err != nil {
		return 0, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	for _, result := range spec.Results {
		if result.Kind != "fingerprint" || result.Status != "draft" {
			continue
		}
		product := Product{Key: spec.ProductKey, Name: spec.Name, Fingerprints: string(result.Template), Evidence: spec.Evidence}
		if _, err := tx.Exec(ctx, `INSERT INTO poc_products(key,profile) VALUES($1,$2) ON CONFLICT(key) DO NOTHING`, spec.ProductKey, product); err != nil {
			return 0, err
		}
	}
	var productKey *string
	if err := tx.QueryRow(ctx, `SELECT (SELECT key FROM poc_products WHERE key=$1)`, spec.ProductKey).Scan(&productKey); err != nil {
		return 0, err
	}
	// spec is the source of truth; YAML is rendered when reading, not stored a second time.
	if generationID == 0 {
		if err := tx.QueryRow(ctx, `INSERT INTO poc_generations(cve_id,product_key,spec,template) VALUES($1,$2,$3,'') RETURNING id`, id, productKey, spec).Scan(&generationID); err != nil {
			return 0, err
		}
	} else {
		tag, err := tx.Exec(ctx, `UPDATE poc_generations SET product_key=$2,spec=$3,template='' WHERE id=$1 AND cve_id=$4`, generationID, productKey, spec, id)
		if err != nil {
			return 0, err
		}
		if tag.RowsAffected() != 1 {
			return 0, errors.New("生成记录不存在")
		}
	}
	return generationID, tx.Commit(ctx)
}

func (s *Service) products(ctx context.Context) ([]Product, error) {
	rows, err := s.db.Query(ctx, `SELECT profile FROM poc_products ORDER BY key`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[Product])
}

func (s *Service) enqueue(ctx context.Context, kind string, input any) (int64, error) {
	var id int64
	err := s.db.QueryRow(ctx, `INSERT INTO poc_jobs(kind,input) VALUES($1,$2) RETURNING id`, kind, input).Scan(&id)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "poc_one_source_job" {
		return 0, errors.New("已有数据同步或搜索任务正在排队或执行，请等待完成")
	}
	return id, err
}
