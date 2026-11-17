package poc

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type sourceError struct{ err error }

func (e *sourceError) Error() string { return e.err.Error() }
func (e *sourceError) Unwrap() error { return e.err }

type syncFailure struct {
	completed int
	err       error
}

func (e *syncFailure) Error() string { return e.err.Error() }
func (e *syncFailure) Unwrap() error { return e.err }

type repoRecord struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Links       []Link `json:"links"`
}
type repositorySource struct{ name, branch, format string }

var repositorySources = []repositorySource{
	{"nomi-sec/PoC-in-GitHub", "master", "json"},
	{"trickest/cve", "main", "markdown"},
	{"projectdiscovery/nuclei-templates", "main", "tree"},
}
var cveInPath = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]{4,}`)
var githubLink = regexp.MustCompile(`https://github\.com/[^\s<>\)\]]+`)

func (c *CVE) mergeLinks() error {
	seen := map[string]struct{}{}
	links := []Link{}
	add := func(link Link) {
		if _, ok := seen[link.URL]; !ok {
			seen[link.URL] = struct{}{}
			links = append(links, link)
		}
	}
	for _, link := range c.Discovered {
		add(link)
	}
	names := make([]string, 0, len(c.Sources))
	for name := range c.Sources {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		var source struct {
			Links []Link `json:"links"`
		}
		if err := json.Unmarshal(c.Sources[name], &source); err != nil {
			return err
		}
		for _, link := range source.Links {
			add(link)
		}
	}
	c.Discovered = links
	return nil
}

func (s *Service) repository(ctx context.Context, source repositorySource, years map[string]struct{}) ([]repoRecord, error) {
	ordered := make([]string, 0, len(years))
	for year := range years {
		ordered = append(ordered, year)
	}
	sort.Strings(ordered)
	cacheKey := "poc:repo:" + source.name + ":" + strings.Join(ordered, ",")
	if s.redis != nil {
		data, err := s.redis.Get(ctx, cacheKey).Bytes()
		if err == nil {
			zr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			defer zr.Close()
			var records []repoRecord
			if err := json.NewDecoder(zr).Decode(&records); err != nil {
				return nil, err
			}
			return records, nil
		} else if !errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("read repository cache %s from redis: %w", cacheKey, err)
		}
	}
	var records []repoRecord
	var err error
	if source.format == "tree" {
		records, err = s.templateIndex(ctx, source, years)
	} else {
		records, err = s.archiveIndex(ctx, source, years)
	}
	if err != nil {
		return nil, err
	}
	if s.redis != nil {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if err := json.NewEncoder(zw).Encode(records); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		if err := s.redis.Set(ctx, cacheKey, buf.Bytes(), 6*time.Hour).Err(); err != nil {
			return nil, fmt.Errorf("cache repository %s to redis: %w", cacheKey, err)
		}
	}
	return records, nil
}

func (s *Service) archiveIndex(ctx context.Context, source repositorySource, years map[string]struct{}) ([]repoRecord, error) {
	address := "https://codeload.github.com/" + source.name + "/tar.gz/refs/heads/" + source.branch
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return nil, err
	}
	client := http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &sourceError{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &sourceError{fmt.Errorf("%s HTTP %d", source.name, resp.StatusCode)}
	}
	compressed, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, &sourceError{err}
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	records := []repoRecord{}
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, &sourceError{err}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		id := strings.TrimSuffix(path.Base(header.Name), path.Ext(header.Name))
		if !cvePattern.MatchString(id) {
			continue
		}
		if _, ok := years[strings.Split(id, "-")[1]]; !ok {
			continue
		}
		_, relative, ok := strings.Cut(header.Name, "/")
		if !ok {
			return nil, &sourceError{errors.New("repository archive path missing root")}
		}
		record := repoRecord{ID: id, URL: "https://github.com/" + source.name + "/blob/" + source.branch + "/" + relative, Links: []Link{}}
		switch source.format {
		case "json":
			if path.Ext(header.Name) != ".json" {
				continue
			}
			var repositories []struct {
				URL         string `json:"html_url"`
				Name        string `json:"full_name"`
				Description string `json:"description"`
			}
			if err := json.NewDecoder(archive).Decode(&repositories); err != nil {
				return nil, &sourceError{fmt.Errorf("%s: %w", relative, err)}
			}
			descriptions := []string{}
			for _, repo := range repositories {
				if repo.URL == "" || repo.Name == "" {
					return nil, &sourceError{fmt.Errorf("%s: missing repository URL/name", relative)}
				}
				record.Links = append(record.Links, Link{repo.URL, repo.Name})
				if repo.Description != "" {
					descriptions = append(descriptions, repo.Description)
				}
			}
			record.Description = strings.Join(descriptions, "\n")
		case "markdown":
			if path.Ext(header.Name) != ".md" {
				continue
			}
			raw, err := io.ReadAll(archive)
			if err != nil {
				return nil, &sourceError{err}
			}
			text := string(raw)
			_, section, found := strings.Cut(text, "### Description")
			if found {
				record.Description = strings.TrimSpace(strings.SplitN(section, "### ", 2)[0])
			}
			_, pocs, found := strings.Cut(text, "#### Github")
			if found {
				pocs = strings.SplitN(pocs, "\n###", 2)[0]
				for _, link := range githubLink.FindAllString(pocs, -1) {
					record.Links = append(record.Links, Link{link, strings.TrimPrefix(link, "https://github.com/")})
				}
			}
		}
		records = append(records, record)
	}
	return records, nil
}

func (s *Service) templateIndex(ctx context.Context, source repositorySource, years map[string]struct{}) ([]repoRecord, error) {
	var tree struct {
		Truncated bool
		Tree      []struct{ Path, Type string }
	}
	if err := s.fetch(ctx, "https://api.github.com/repos/"+source.name+"/git/trees/"+source.branch+"?recursive=1", &tree, nil); err != nil {
		return nil, err
	}
	if tree.Truncated {
		return nil, &sourceError{errors.New("GitHub template tree was truncated")}
	}
	byID := map[string]*repoRecord{}
	for _, entry := range tree.Tree {
		if entry.Type != "blob" || path.Ext(entry.Path) != ".yaml" {
			continue
		}
		for _, id := range cveInPath.FindAllString(entry.Path, -1) {
			if _, ok := years[strings.Split(id, "-")[1]]; !ok {
				continue
			}
			link := "https://github.com/" + source.name + "/blob/" + source.branch + "/" + entry.Path
			record, ok := byID[id]
			if !ok {
				record = &repoRecord{ID: id, URL: link, Description: "Nuclei CVE template: " + entry.Path, Links: []Link{}}
				byID[id] = record
			}
			record.Links = append(record.Links, Link{link, "Nuclei: " + entry.Path})
		}
	}
	records := make([]repoRecord, 0, len(byID))
	for _, record := range byID {
		records = append(records, *record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

func (s *Service) syncRepository(ctx context.Context, source repositorySource, years map[string]struct{}, ids map[string]struct{}, progress func(string) error) error {
	records, err := s.repository(ctx, source, years)
	if err != nil {
		return err
	}
	for i, record := range records {
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if err := s.ingest(ctx, record.ID, source.name, raw); err != nil {
			return err
		}
		ids[record.ID] = struct{}{}
		if (i+1)%200 == 0 {
			if err := progress(fmt.Sprintf("%s: %d/%d", source.name, i+1, len(records))); err != nil {
				return err
			}
		}
	}
	return progress(fmt.Sprintf("%s: 已导入 %d 个 CVE", source.name, len(records)))
}

func (s *Service) search(ctx context.Context, id string) error {
	resolved, err := s.refreshCVE(ctx, id)
	if err != nil {
		return err
	}
	failures := []error{}
	for _, notice := range resolved.Notices {
		failures = append(failures, errors.New(notice))
	}
	if err := s.searchRepositories(ctx, id); err != nil {
		var remote *sourceError
		if !errors.As(err, &remote) {
			return err
		}
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		return &syncFailure{1, errors.Join(failures...)}
	}
	return nil
}
