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
	ID          string     `json:"id"`
	Description string     `json:"description"`
	URL         string     `json:"url"`
	Links       []Link     `json:"links"`
	Templates   []Evidence `json:"templates,omitempty"`
}
type repositorySource struct{ name, branch, format string }

var nucleiRepository = repositorySource{"projectdiscovery/nuclei-templates", "main", "tree"}

var repositorySources = []repositorySource{
	{"nomi-sec/PoC-in-GitHub", "master", "json"},
	{"trickest/cve", "main", "markdown"},
	nucleiRepository,
}
var cveInPath = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]{4,}`)
var githubLink = regexp.MustCompile(`https://github\.com/[^\s<>\)\]]+`)

func (record *repoRecord) readPoCs(reader io.Reader) error {
	var entries []struct {
		URL         string `json:"html_url"`
		Name        string `json:"full_name"`
		Description string
	}
	if err := json.NewDecoder(reader).Decode(&entries); err != nil {
		return &sourceError{err}
	}
	descriptions := []string{}
	for _, entry := range entries {
		if entry.URL == "" || entry.Name == "" {
			return &sourceError{errors.New("PoC index missing repository URL/name")}
		}
		record.Links = append(record.Links, Link{URL: entry.URL, Title: entry.Name})
		if entry.Description != "" {
			descriptions = append(descriptions, entry.Description)
		}
	}
	record.Description = strings.Join(descriptions, "\n")
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
	records, err := func() ([]repoRecord, error) {
		if source.format == "tree" {
			records, err := s.archiveIndex(ctx, repositorySource{source.name, source.branch, "yaml"}, years)
			if err == nil {
				return records, nil
			}
			return s.templateIndex(ctx, source, years)
		}
		return s.archiveIndex(ctx, source, years)
	}()
	if err != nil {
		return nil, err
	}
	if s.redis != nil {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if err := json.NewEncoder(zw).Encode(records); err == nil && zw.Close() == nil {
			_ = s.redis.Set(ctx, cacheKey, buf.Bytes(), 24*time.Hour).Err()
		}
	}
	return records, nil
}

func (s *Service) archiveIndex(ctx context.Context, source repositorySource, years map[string]struct{}) ([]repoRecord, error) {
	address := fmt.Sprintf("https://api.github.com/repos/%s/tarball/%s", source.name, source.branch)
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "devsecops-cve")
	if s.cfg.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.GitHubToken)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, &sourceError{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, &sourceError{fmt.Errorf("download archive: HTTP %d", resp.StatusCode)}
	}
	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, &sourceError{err}
	}
	defer gzipReader.Close()
	archive := tar.NewReader(gzipReader)
	records := []repoRecord{}
	templates := map[string]*repoRecord{}
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, &sourceError{err}
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if source.format == "yaml" {
			if path.Ext(header.Name) != ".yaml" && path.Ext(header.Name) != ".yml" {
				continue
			}
			ids := cveInPath.FindAllString(header.Name, -1)
			if len(ids) == 0 {
				continue
			}
			matched := false
			for _, id := range ids {
				if _, ok := years[strings.Split(id, "-")[1]]; ok {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			raw, err := io.ReadAll(archive)
			if err != nil {
				return nil, &sourceError{err}
			}
			body := strings.TrimSpace(string(raw))
			if len(body) == 0 {
				continue
			}
			_, relative, ok := strings.Cut(header.Name, "/")
			if !ok {
				return nil, &sourceError{errors.New("repository archive path missing root")}
			}
			link := "https://github.com/" + source.name + "/blob/" + source.branch + "/" + relative
			for _, id := range ids {
				if _, ok := years[strings.Split(id, "-")[1]]; !ok {
					continue
				}
				record := templates[id]
				if record == nil {
					record = &repoRecord{ID: id, URL: link, Description: "Nuclei CVE template: " + relative, Links: []Link{}, Templates: []Evidence{}}
					templates[id] = record
				}
				record.Links = append(record.Links, Link{URL: link, Title: "Nuclei: " + relative})
				record.Templates = append(record.Templates, Evidence{Source: link, Text: string(body)})
			}
			continue
		}
		id := strings.TrimSuffix(path.Base(header.Name), path.Ext(header.Name))
		if !ValidCVE(id) {
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
			if err := record.readPoCs(archive); err != nil {
				return nil, fmt.Errorf("%s: %w", relative, err)
			}
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
					record.Links = append(record.Links, Link{URL: link, Title: strings.TrimPrefix(link, "https://github.com/")})
				}
			}
		}
		records = append(records, record)
	}
	for _, record := range templates {
		records = append(records, *record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
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
		if entry.Type != "blob" || (path.Ext(entry.Path) != ".yaml" && path.Ext(entry.Path) != ".yml") {
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
			record.Links = append(record.Links, Link{URL: link, Title: "Nuclei: " + entry.Path})
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
	var records []repoRecord
	var err error
	if source.name == nucleiRepository.name {
		records, err = s.archiveIndex(ctx, repositorySource{source.name, source.branch, "yaml"}, years)
	} else {
		records, err = s.repository(ctx, source, years)
	}
	if err != nil {
		return err
	}
	for i, record := range records {
		if err := s.ingest(ctx, record.ID, source.name, record); err != nil {
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
