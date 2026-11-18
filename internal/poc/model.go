package poc

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"
)

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

type Link struct {
	URL   string `json:"url"`
	Title string `json:"title"`
}

type Manual struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	PoCs        []Link `json:"pocs"`
	Notes       string `json:"notes"`
}

type CVE struct {
	ID         string                     `json:"id"`
	Sources    map[string]json.RawMessage `json:"sources"`
	Discovered []Link                     `json:"discovered"`
	Manual     Manual                     `json:"manual"`
	SearchedAt *time.Time                 `json:"searched_at"`
	UpdatedAt  time.Time                  `json:"updated_at"`
}

type CVEFilter struct {
	Query  string
	Source string
	Year   string
	Start  string
	End    string
	Limit  int
}

func ValidCVE(id string) bool {
	return cvePattern.MatchString(id)
}

func (c *CVE) MergeLinks() error {
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

type Evidence struct {
	Source string `json:"source"`
	Text   string `json:"text"`
}

type Product struct {
	Key              string     `json:"key"`
	Name             string     `json:"name"`
	Fingerprints     string     `json:"fingerprints"`
	VersionEndpoints string     `json:"version_endpoints"`
	Evidence         []Evidence `json:"evidence"`
}

type GenerateInput struct {
	IDs []string `json:"ids"`
}

type PoCResult struct {
	Kind               string          `json:"kind"`
	Status             string          `json:"status"`
	Reason             string          `json:"reason"`
	MissingInformation []string        `json:"missing_information"`
	Template           json.RawMessage `json:"template"`
}

type Spec struct {
	Version        int         `json:"version"`
	ProductKey     string      `json:"product_key"`
	Name           string      `json:"name"`
	MappingCommand string      `json:"mapping_command,omitempty"`
	Results        []PoCResult `json:"results"`
	Evidence       []Evidence  `json:"evidence"`
}

type Generation struct {
	ID        int64             `json:"id"`
	CVEID     string            `json:"cve_id"`
	Spec      Spec              `json:"spec"`
	Templates map[string]string `json:"templates"`
	CreatedAt time.Time         `json:"created_at"`
}

type GenerationContext struct {
	CVE         CVE        `json:"cve"`
	Description string     `json:"description"`
	Products    []Product  `json:"products"`
	Materials   []Evidence `json:"materials"`
	Notices     []string   `json:"notices"`
	Templates   []Evidence `json:"templates"`
}

type SyncInput struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

func (in SyncInput) Dates() (time.Time, time.Time, error) {
	start, err := time.Parse("2006-01-02", in.Start)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("开始日期须为 YYYY-MM-DD")
	}
	end, err := time.Parse("2006-01-02", in.End)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("结束日期须为 YYYY-MM-DD")
	}
	if end.Before(start) {
		return time.Time{}, time.Time{}, errors.New("结束日期不能早于开始日期")
	}
	return start, end.Add(24*time.Hour - time.Millisecond), nil
}

type Job struct {
	ID         int64      `json:"id"`
	Kind       string     `json:"kind"`
	Status     string     `json:"status"`
	Progress   string     `json:"progress"`
	Error      string     `json:"error"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

type lookupResult struct {
	CVE     CVE
	Notices []string
}
