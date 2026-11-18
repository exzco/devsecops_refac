package poc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

func syncWindows(ctx context.Context, start, end time.Time, run func(time.Time, time.Time) error) error {
	for from := start; !from.After(end); {
		until := from.AddDate(0, 0, 30).Add(-time.Millisecond)
		if until.After(end) {
			until = end
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := run(from, until); err != nil {
			return err
		}
		from = until.Add(time.Millisecond)
		if !from.After(end) {
			if err := wait(ctx, 6*time.Second); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Service) syncCVE(ctx context.Context, in SyncInput, progress func(string) error) error {
	start, end, err := in.Dates()
	if err != nil {
		return err
	}
	ids := map[string]struct{}{}
	recentIDs := map[string]struct{}{}
	years := map[string]struct{}{}
	for year := start.Year(); year <= end.Year(); year++ {
		years[fmt.Sprint(year)] = struct{}{}
	}
	sources := []struct {
		name string
		run  func() error
	}{
		{"projectdiscovery/nuclei-templates", func() error { return s.syncRepository(ctx, repositorySources[2], years, ids, progress) }},
		{"nomi-sec/PoC-in-GitHub", func() error { return s.syncRepository(ctx, repositorySources[0], years, ids, progress) }},
		{"trickest/cve", func() error { return s.syncRepository(ctx, repositorySources[1], years, ids, progress) }},
		{"GitHub Advisories", func() error {
			return syncWindows(ctx, start, end, func(from, until time.Time) error {
				if err := progress("GitHub 公告 " + from.Format("2006-01-02") + " 至 " + until.Format("2006-01-02")); err != nil {
					return err
				}
				return s.advisories(ctx, url.Values{"modified": {from.Format("2006-01-02") + ".." + until.Format("2006-01-02")}, "sort": {"updated"}, "direction": {"asc"}}, recentIDs)
			})
		}},
		{"GitHub 仓库搜索", func() error { return s.searchMissing(ctx, recentIDs, progress) }},
	}
	completed := 0
	failures := []error{}
	summary := []string{}
	for _, source := range sources {
		if err := progress(strings.Join(append(summary, source.name+"：同步中"), "；")); err != nil {
			return err
		}
		err := source.run()
		if err != nil {
			var remote *sourceError
			if !errors.As(err, &remote) {
				return err
			}
			failures = append(failures, fmt.Errorf("%s: %w", source.name, err))
			summary = append(summary, source.name+"：失败")
		} else {
			completed++
			summary = append(summary, source.name+"：完成")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	for id := range recentIDs {
		ids[id] = struct{}{}
	}
	if err := progress(fmt.Sprintf("处理 %d 个 CVE；%s", len(ids), strings.Join(summary, "；"))); err != nil {
		return err
	}
	if len(failures) > 0 {
		return &syncFailure{completed, errors.Join(failures...)}
	}
	return nil
}
func (s *Service) advisories(ctx context.Context, q url.Values, ids map[string]struct{}) error {
	q.Set("per_page", "100")
	next := "https://api.github.com/advisories?" + q.Encode()
	for next != "" {
		var entries []json.RawMessage
		if err := s.fetch(ctx, next, &entries, &next); err != nil {
			return err
		}
		for _, raw := range entries {
			var v struct {
				CVEID  string `json:"cve_id"`
				GHSAID string `json:"ghsa_id"`
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				return err
			}
			if v.GHSAID == "" || (q.Get("cve_id") != "" && v.CVEID != q.Get("cve_id")) {
				return &sourceError{errors.New("advisory ID mismatch")}
			}
			if v.CVEID == "" {
				continue
			}
			if err := s.ingest(ctx, v.CVEID, "github:"+v.GHSAID, raw); err != nil {
				return err
			}
			ids[v.CVEID] = struct{}{}
		}
		if next != "" {
			if err := wait(ctx, time.Second); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Service) searchMissing(ctx context.Context, ids map[string]struct{}, progress func(string) error) error {
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] > ordered[j] })
	count := 0
	const maxSearch = 50
	for _, id := range ordered {
		if count >= maxSearch {
			break
		}
		c, err := s.get(ctx, id)
		if err != nil {
			return err
		}
		if len(c.Discovered) > 0 || len(c.Manual.PoCs) > 0 || (c.SearchedAt != nil && time.Since(*c.SearchedAt) < 24*time.Hour) {
			continue
		}
		if err := s.searchRepositories(ctx, id); err != nil {
			return err
		}
		count++
		if err := progress(fmt.Sprintf("GitHub 补充搜索 %d/%d，当前 %s；共收录 %d 个 CVE", count, maxSearch, id, len(ids))); err != nil {
			return err
		}
		if err := wait(ctx, 7*time.Second); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) searchRepositories(ctx context.Context, id string) error {
	if !ValidCVE(id) {
		return errors.New("invalid CVE ID")
	}
	var result struct {
		Incomplete bool `json:"incomplete_results"`
		Items      []struct {
			HTMLURL string `json:"html_url"`
			Name    string `json:"full_name"`
		}
	}
	q := url.Values{"q": {id + " in:name,description,readme"}, "per_page": {"10"}, "sort": {"stars"}}
	if err := s.fetch(ctx, "https://api.github.com/search/repositories?"+q.Encode(), &result, nil); err != nil {
		return err
	}
	if result.Incomplete {
		return &sourceError{errors.New("GitHub search incomplete; retry this CVE later")}
	}
	links := []Link{}
	for _, r := range result.Items {
		links = append(links, Link{URL: r.HTMLURL, Title: r.Name})
	}
	tag, err := s.db.Exec(ctx, `UPDATE poc_cves SET discovered=$2,searched_at=now(),updated_at=now() WHERE id=$1`, id, links)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("CVE not found")
	}
	s.invalidate(ctx, id)
	return nil
}

