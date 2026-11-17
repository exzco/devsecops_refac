package poc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/sync/errgroup"
)

type lookupResult struct {
	CVE     CVE
	Notices []string
}

func (s *Service) resolve(ctx context.Context, id string) (lookupResult, error) {
	cve, err := s.get(ctx, id)
	if err == nil {
		if _, ok := cve.Sources["CVEProject/cvelistV5"]; ok {
			return lookupResult{cve, []string{}}, nil
		}
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return lookupResult{}, err
	}
	return s.refreshCVE(ctx, id)
}
func (s *Service) refreshCVE(ctx context.Context, id string) (lookupResult, error) {
	if !cvePattern.MatchString(id) {
		return lookupResult{}, errors.New("请输入有效 CVE 编号")
	}
	result := s.lookups.DoChan(id, func() (any, error) {
		lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 25*time.Second)
		defer cancel()
		sources := []struct {
			name string
			run  func(context.Context, string) error
		}{
			{"CVEProject/cvelistV5", s.lookupOfficial}, {"nomi-sec/PoC-in-GitHub", s.lookupPoCs}, {"GitHub Advisories", s.lookupAdvisories},
		}
		notices := make([]string, len(sources))
		group, groupCtx := errgroup.WithContext(lookupCtx)
		for i, source := range sources {
			group.Go(func() error {
				sourceCtx, cancel := context.WithTimeout(groupCtx, 12*time.Second)
				defer cancel()
				if err := source.run(sourceCtx, id); err != nil {
					var remote *sourceError
					if !errors.As(err, &remote) {
						return err
					}
					notices[i] = source.name + ": " + err.Error()
				}
				return nil
			})
		}
		if err := group.Wait(); err != nil {
			return nil, err
		}
		warnings := []string{}
		for _, notice := range notices {
			if notice != "" {
				warnings = append(warnings, notice)
			}
		}
		cve, err := s.get(lookupCtx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%s 未取得记录；%s", id, strings.Join(warnings, "；"))
		}
		if err != nil {
			return nil, err
		}
		return lookupResult{cve, warnings}, nil
	})
	select {
	case <-ctx.Done():
		return lookupResult{}, ctx.Err()
	case r := <-result:
		if r.Err != nil {
			return lookupResult{}, r.Err
		}
		value, ok := r.Val.(lookupResult)
		if !ok {
			return lookupResult{}, errors.New("invalid CVE lookup result")
		}
		return value, nil
	}
}
func (s *Service) lookupOfficial(ctx context.Context, id string) error {
	parts := strings.Split(id, "-")
	number := parts[2]
	bucket := number[:len(number)-3] + "xxx"
	address := "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/" + parts[1] + "/" + bucket + "/" + id + ".json"
	var raw json.RawMessage
	if err := s.fetch(ctx, address, &raw, nil); err != nil {
		return err
	}
	var record struct {
		Metadata struct {
			ID    string `json:"cveId"`
			State string
		} `json:"cveMetadata"`
		Containers struct {
			CNA struct {
				Descriptions []struct{ Lang, Value string }
				References   []struct{ URL string }
				Affected     json.RawMessage
			}
		} `json:"containers"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return &sourceError{err}
	}
	if record.Metadata.ID != id {
		return &sourceError{errors.New("CVE record ID mismatch")}
	}
	description := ""
	for _, desc := range record.Containers.CNA.Descriptions {
		if desc.Lang == "en" {
			description = desc.Value
			break
		}
	}
	links := []Link{}
	for _, reference := range record.Containers.CNA.References {
		links = append(links, Link{reference.URL, "CVE 官方引用"})
	}
	normalized, err := json.Marshal(map[string]any{"description": description, "url": address, "state": record.Metadata.State, "affected": record.Containers.CNA.Affected, "references": links, "record": raw})
	if err != nil {
		return err
	}
	return s.ingest(ctx, id, "CVEProject/cvelistV5", normalized)
}
func (s *Service) lookupPoCs(ctx context.Context, id string) error {
	address := "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/" + strings.Split(id, "-")[1] + "/" + id + ".json"
	var entries []struct {
		URL         string `json:"html_url"`
		Name        string `json:"full_name"`
		Description string
	}
	if err := s.fetch(ctx, address, &entries, nil); err != nil {
		return err
	}
	record := repoRecord{ID: id, URL: address, Links: []Link{}}
	descriptions := []string{}
	for _, entry := range entries {
		if entry.URL == "" || entry.Name == "" {
			return &sourceError{errors.New("PoC index missing repository URL/name")}
		}
		record.Links = append(record.Links, Link{entry.URL, entry.Name})
		if entry.Description != "" {
			descriptions = append(descriptions, entry.Description)
		}
	}
	record.Description = strings.Join(descriptions, "\n")
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.ingest(ctx, id, "nomi-sec/PoC-in-GitHub", raw)
}
func (s *Service) lookupAdvisories(ctx context.Context, id string) error {
	next := "https://api.github.com/advisories?cve_id=" + url.QueryEscape(id) + "&per_page=100"
	for next != "" {
		var records []json.RawMessage
		if err := s.fetch(ctx, next, &records, &next); err != nil {
			return err
		}
		for _, raw := range records {
			var record struct {
				CVEID  string `json:"cve_id"`
				GHSAID string `json:"ghsa_id"`
			}
			if err := json.Unmarshal(raw, &record); err != nil {
				return &sourceError{err}
			}
			if record.CVEID != id || record.GHSAID == "" {
				return &sourceError{errors.New("advisory ID mismatch")}
			}
			if err := s.ingest(ctx, id, "github:"+record.GHSAID, raw); err != nil {
				return err
			}
		}
	}
	return nil
}
