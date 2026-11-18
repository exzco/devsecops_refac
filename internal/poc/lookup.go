package poc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
)

func (s *Service) resolve(ctx context.Context, id string) (lookupResult, error) {
	if s.redis != nil {
		if data, err := s.redis.Get(ctx, "poc:cve:"+id).Bytes(); err == nil {
			var cve CVE
			if err := json.Unmarshal(data, &cve); err == nil {
				return lookupResult{cve, []string{}}, nil
			}
		}
	}
	cve, err := s.get(ctx, id)
	if err == nil {
		if s.redis != nil {
			if raw, err := json.Marshal(cve); err == nil {
				_ = s.redis.Set(ctx, "poc:cve:"+id, raw, 24*time.Hour).Err()
			}
		}
		return lookupResult{cve, []string{}}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return lookupResult{}, err
	}
	return s.refreshCVE(ctx, id)
}

func (s *Service) refreshCVE(ctx context.Context, id string) (lookupResult, error) {
	if !ValidCVE(id) {
		return lookupResult{}, errors.New("请输入有效 CVE 编号")
	}
	result := s.lookups.DoChan(id, func() (any, error) {
		lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 25*time.Second)
		defer cancel()
		sources := []struct {
			name string
			run  func(context.Context, string) error
		}{
			{"CVEProject/cvelistV5", s.lookupOfficial}, {"nomi-sec/PoC-in-GitHub", s.lookupPoCs},
			{"GitHub Advisories", func(ctx context.Context, id string) error {
				return s.advisories(ctx, url.Values{"cve_id": {id}}, map[string]struct{}{})
			}},
			{nucleiRepository.name, s.lookupNuclei},
		}
		group, fetchCtx := errgroup.WithContext(lookupCtx)
		failures := make([]string, len(sources))
		for i, source := range sources {
			group.Go(func() error {
				if err := source.run(fetchCtx, id); err != nil {
					failures[i] = fmt.Sprintf("%s 暂时不可用：%v", source.name, err)
				}
				return nil
			})
		}
		_ = group.Wait()
		cve, err := s.get(lookupCtx, id)
		if err != nil {
			notices := []string{}
			for _, failure := range failures {
				if failure != "" {
					notices = append(notices, failure)
				}
			}
			if len(notices) > 0 {
				return lookupResult{}, errors.New(strings.Join(notices, "；"))
			}
			return lookupResult{}, err
		}
		notices := []string{}
		for _, failure := range failures {
			if failure != "" {
				notices = append(notices, failure)
			}
		}
		return lookupResult{cve, notices}, nil
	})
	select {
	case <-ctx.Done():
		return lookupResult{}, ctx.Err()
	case res := <-result:
		if res.Err != nil {
			return lookupResult{}, res.Err
		}
		return res.Val.(lookupResult), nil
	}
}

func (s *Service) lookupOfficial(ctx context.Context, id string) error {
	parts := strings.Split(id, "-")
	year, seq := parts[1], parts[2]
	dir := seq[:max(len(seq)-3, 1)] + "xxx"
	address := fmt.Sprintf("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/%s/%s/%s.json", year, dir, id)
	var raw json.RawMessage
	if err := s.fetch(ctx, address, &raw, nil); err != nil {
		return err
	}
	var cve struct {
		Containers struct {
			Cna struct {
				Descriptions []struct{ Lang, Value string } `json:"descriptions"`
				References   []struct{ URL string }          `json:"references"`
			} `json:"cna"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(raw, &cve); err != nil {
		return err
	}
	links := make([]Link, 0, len(cve.Containers.Cna.References))
	for _, ref := range cve.Containers.Cna.References {
		links = append(links, Link{URL: ref.URL})
	}
	description := ""
	for _, d := range cve.Containers.Cna.Descriptions {
		if d.Lang == "en" && d.Value != "" {
			description = d.Value
			break
		}
		if description == "" {
			description = d.Value
		}
	}
	return s.ingest(ctx, id, "CVEProject/cvelistV5", map[string]any{"id": id, "description": description, "links": links})
}

func (s *Service) lookupPoCs(ctx context.Context, id string) error {
	year := strings.Split(id, "-")[1]
	address := fmt.Sprintf("https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/%s/%s.json", year, id)
	var entries []struct {
		Name        string `json:"name"`
		URL         string `json:"html_url"`
		Description string `json:"description"`
	}
	if err := s.fetch(ctx, address, &entries, nil); err != nil {
		return err
	}
	links := make([]Link, 0, len(entries))
	descriptions := make([]string, 0, len(entries))
	for _, entry := range entries {
		links = append(links, Link{URL: entry.URL, Title: entry.Name})
		if entry.Description != "" {
			descriptions = append(descriptions, entry.Name+": "+entry.Description)
		}
	}
	return s.ingest(ctx, id, "nomi-sec/PoC-in-GitHub", map[string]any{"id": id, "links": links, "description": strings.Join(descriptions, "\n")})
}

func (s *Service) search(ctx context.Context, id string) error {
	links, err := s.searchPoCs(ctx, id)
	if err != nil {
		return err
	}
	return s.saveSearchLinks(ctx, id, links)
}

func (s *Service) searchPoCs(ctx context.Context, id string) ([]Link, error) {
	if !ValidCVE(id) {
		return nil, errors.New("invalid CVE ID")
	}
	result := []Link{}
	for _, q := range []string{id + " poc in:name,description", id + " exploit in:name,description"} {
		var resp struct {
			Items []struct {
				URL         string `json:"html_url"`
				Description string `json:"description"`
			} `json:"items"`
		}
		if err := s.fetch(ctx, "https://api.github.com/search/repositories?q="+url.QueryEscape(q)+"&per_page=10", &resp, nil); err != nil {
			var srcErr *sourceError
			if errors.As(err, &srcErr) && strings.Contains(srcErr.Error(), "HTTP 403") {
				return result, nil
			}
			return nil, err
		}
		for _, item := range resp.Items {
			result = append(result, Link{URL: item.URL, Title: item.Description})
		}
	}
	return result, nil
}

func (s *Service) saveSearchLinks(ctx context.Context, id string, links []Link) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var discovered []Link
	if err := tx.QueryRow(ctx, `SELECT discovered FROM poc_cves WHERE id=$1 FOR UPDATE`, id).Scan(&discovered); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}
	seen := map[string]struct{}{}
	for _, link := range discovered {
		seen[link.URL] = struct{}{}
	}
	for _, link := range links {
		if _, ok := seen[link.URL]; !ok {
			seen[link.URL] = struct{}{}
			discovered = append(discovered, link)
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO poc_cves(id,sources,discovered,searched_at) VALUES($1,'{}',$2,now()) ON CONFLICT(id) DO UPDATE SET discovered=$2,searched_at=now(),updated_at=now()`, id, discovered)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.invalidate(ctx, id)
	return nil
}

func storedNuclei(cve CVE) ([]Evidence, error) {
	raw, ok := cve.Sources[nucleiRepository.name]
	if !ok {
		return nil, nil
	}
	var record repoRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, err
	}
	return record.Templates, nil
}

func (s *Service) lookupNuclei(ctx context.Context, id string) error {
	materials, err := s.nucleiMaterials(ctx, id)
	if err != nil {
		return err
	}
	links := make([]Link, 0, len(materials))
	for _, material := range materials {
		links = append(links, Link{URL: material.Source, Title: "Nuclei YAML: " + id})
	}
	return s.ingest(ctx, id, nucleiRepository.name, map[string]any{"id": id, "links": links, "templates": materials})
}

// nucleiMaterials reads template files as evidence; it never executes them.
func (s *Service) nucleiMaterials(ctx context.Context, id string) ([]Evidence, error) {
	if !ValidCVE(id) {
		return nil, errors.New("读取 Nuclei 模板需要有效 CVE 编号")
	}
	cacheKey := "poc:nuclei:materials:" + id
	if s.redis != nil {
		raw, err := s.redis.Get(ctx, cacheKey).Bytes()
		if err == nil {
			var materials []Evidence
			if err := json.Unmarshal(raw, &materials); err != nil {
				return nil, err
			}
			return materials, nil
		}
		if !errors.Is(err, redis.Nil) {
			return nil, err
		}
	}
	year := strings.Split(id, "-")[1]
	records, err := s.repository(ctx, nucleiRepository, map[string]struct{}{year: {}})
	if err != nil {
		return nil, fmt.Errorf("读取 Nuclei 文件索引: %w", err)
	}
	materials := []Evidence{}
	for _, record := range records {
		if record.ID != id {
			continue
		}
		for _, link := range record.Links {
			prefix := "https://github.com/" + nucleiRepository.name + "/blob/" + nucleiRepository.branch + "/"
			file, ok := strings.CutPrefix(link.URL, prefix)
			if !ok {
				return nil, fmt.Errorf("Nuclei 索引包含非预期文件地址: %s", link.URL)
			}
			address := url.URL{
				Scheme:   "https",
				Host:     "api.github.com",
				Path:     "/repos/" + nucleiRepository.name + "/contents/" + file,
				RawQuery: url.Values{"ref": {nucleiRepository.branch}}.Encode(),
			}
			var content struct {
				Encoding string `json:"encoding"`
				Content  string `json:"content"`
			}
			if err := s.fetch(ctx, address.String(), &content, nil); err != nil {
				return nil, fmt.Errorf("读取 Nuclei YAML %s: %w", file, err)
			}
			if content.Encoding != "base64" {
				return nil, fmt.Errorf("Nuclei YAML %s: 不支持的内容编码 %q", file, content.Encoding)
			}
			body, err := base64.StdEncoding.DecodeString(content.Content)
			if err != nil {
				return nil, fmt.Errorf("解码 Nuclei YAML %s: %w", file, err)
			}
			if len(body) == 0 {
				return nil, fmt.Errorf("Nuclei YAML %s 内容为空", file)
			}
			materials = append(materials, Evidence{Source: link.URL, Text: string(body)})
		}
	}
	if s.redis != nil {
		raw, err := json.Marshal(materials)
		if err != nil {
			return nil, err
		}
		if err := s.redis.Set(ctx, cacheKey, raw, 6*time.Hour).Err(); err != nil {
			return nil, err
		}
	}
	return materials, nil
}
