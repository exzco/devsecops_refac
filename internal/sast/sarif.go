package sast

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// 原始 json
type sarifMessage struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`

	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`

	Properties struct {
		SecuritySeverity string   `json:"security-severity"`
		Tags             []string `json:"tags"`
	} `json:"properties"`
}

type sarifLocation struct {
	ID      *int         `json:"id"`
	Message sarifMessage `json:"message"`

	PhysicalLocation struct {
		ArtifactLocation struct {
			URI   string `json:"uri"`
			Index *int   `json:"index"`
		} `json:"artifactLocation"`

		Region struct {
			StartLine   int          `json:"startLine"`
			StartColumn int          `json:"startColumn"`
			EndLine     int          `json:"endLine"`
			EndColumn   int          `json:"endColumn"`
			Snippet     sarifMessage `json:"snippet"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           *int              `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	RelatedLocations    []sarifLocation   `json:"relatedLocations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`

	CodeFlows []struct {
		ThreadFlows []struct {
			Locations []struct {
				Location sarifLocation `json:"location"`
				Kinds    []string      `json:"kinds"`
			} `json:"locations"`
		} `json:"threadFlows"`
	} `json:"codeFlows"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Rules []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`

	Artifacts []struct {
		Location struct {
			URI string `json:"uri"`
		} `json:"location"`
	} `json:"artifacts"`

	Results []sarifResult `json:"results"`
}

type sarifReport struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

func convertSARIFLocation(loc sarifLocation, artifactURIs []string) CodeLocation {
	physical := loc.PhysicalLocation
	artifact := physical.ArtifactLocation
	region := physical.Region
	file := artifact.URI

	if file == "" && artifact.Index != nil {
		index := *artifact.Index
		if index >= 0 && index < len(artifactURIs) {
			file = artifactURIs[index]
		}
	}

	endLine := region.EndLine
	if endLine == 0 {
		endLine = region.StartLine
	}

	startColumn := region.StartColumn
	if startColumn == 0 && region.StartLine > 0 {
		startColumn = 1
	}

	return CodeLocation{
		ID:          loc.ID,
		File:        file,
		StartLine:   region.StartLine,
		StartColumn: startColumn,
		EndLine:     endLine,
		EndColumn:   region.EndColumn,
		Message:     loc.Message.Text,
		Snippet:     region.Snippet.Text,
	}
}

func convertSARIFLocations(locations []sarifLocation, artifactURIs []string) []CodeLocation {
	converted := make([]CodeLocation, 0, len(locations))
	for _, loc := range locations {
		converted = append(converted, convertSARIFLocation(loc, artifactURIs))
	}
	return converted
}

// 最终产出 Finding model
type Finding struct {
	RuleID        string            `json:"rule_id"`
	Title         string            `json:"title"`
	Message       string            `json:"message"`
	Level         string            `json:"level"`
	SecurityScore *float64          `json:"security_score,omitempty"`
	CWEs          []string          `json:"cwes"`
	Locations     []CodeLocation    `json:"locations"`
	Related       []CodeLocation    `json:"related_locations"`
	CodeFlows     []CodeFlow        `json:"code_flows"`
	Fingerprints  map[string]string `json:"fingerprints"`
}

type CodeLocation struct {
	ID          *int   `json:"id,omitempty"`
	File        string `json:"file"`
	StartLine   int    `json:"start_line,omitempty"`
	StartColumn int    `json:"start_column,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	EndColumn   int    `json:"end_column,omitempty"`
	Message     string `json:"message,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
}

type CodeFlow struct {
	ThreadFlows []ThreadFlow `json:"thread_flows"`
}

type ThreadFlow struct {
	Steps []FlowStep `json:"steps"`
}

type FlowStep struct {
	Location CodeLocation `json:"location"`
	Kinds    []string     `json:"kinds,omitempty"`
}

// 目前只有支持 2.1.0 sarif 格式
func ParseSARIF(r io.Reader) ([]Finding, error) {
	var report sarifReport

	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&report); err != nil {
		return nil, fmt.Errorf("decode SARIF: %w", err)
	}

	// 一个报告包含一个完整的 JSON 文档。
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("invalid trailing SARIF content: %w", err)
		}
		return nil, fmt.Errorf("multiple JSON documents in SARIF")
	}

	if report.Version != "2.1.0" {
		return nil, fmt.Errorf(
			"unsupported SARIF version: %q", report.Version,
		)
	}

	findings := make([]Finding, 0)

	for runIndex, run := range report.Runs {
		rules := run.Tool.Driver.Rules

		// 用规则 ID 查找标题、安全评分和 CWE。
		rulesByID := make(map[string]sarifRule, len(rules))
		for _, rule := range rules {
			rulesByID[rule.ID] = rule
		}

		artifactURIs := make([]string, len(run.Artifacts))
		for i, artifact := range run.Artifacts {
			artifactURIs[i] = artifact.Location.URI
		}

		for resultIndex, result := range run.Results {
			ruleID := result.RuleID

			// 没有 ruleId 时，通过 ruleIndex 查找。
			if ruleID == "" && result.RuleIndex != nil {
				index := *result.RuleIndex
				if index < 0 || index >= len(rules) {
					return nil, fmt.Errorf(
						"run %d result %d: invalid rule index %d",
						runIndex, resultIndex, index,
					)
				}
				ruleID = rules[index].ID
			}

			if ruleID == "" {
				return nil, fmt.Errorf(
					"run %d result %d: missing rule ID",
					runIndex, resultIndex,
				)
			}

			rule := rulesByID[ruleID]

			finding := Finding{
				RuleID:       ruleID,
				Title:        rule.ShortDescription.Text,
				Message:      result.Message.Text,
				Level:        result.Level,
				CWEs:         make([]string, 0),
				CodeFlows:    make([]CodeFlow, 0),
				Fingerprints: result.PartialFingerprints,
			}

			if finding.Title == "" {
				finding.Title = ruleID
			}

			if finding.Level == "" {
				finding.Level = rule.DefaultConfiguration.Level
			}
			if finding.Level == "" {
				finding.Level = "warning"
			}

			if rawScore := rule.Properties.SecuritySeverity; rawScore != "" {
				score, err := strconv.ParseFloat(rawScore, 64)
				if err != nil || !(score >= 0 && score <= 10) {
					return nil, fmt.Errorf(
						"rule %s: invalid security severity %q",
						ruleID, rawScore,
					)
				}
				finding.SecurityScore = &score
			}

			for _, tag := range rule.Properties.Tags {
				if strings.HasPrefix(tag, "external/cwe/cwe-") {
					cwe := strings.TrimPrefix(tag, "external/cwe/")
					finding.CWEs = append(finding.CWEs, strings.ToUpper(cwe))
				}
			}

			finding.Locations = convertSARIFLocations(result.Locations, artifactURIs)
			finding.Related = convertSARIFLocations(result.RelatedLocations, artifactURIs)

			// 保留每条路径及其节点顺序。
			for _, rawFlow := range result.CodeFlows {
				flow := CodeFlow{
					ThreadFlows: make([]ThreadFlow, 0),
				}

				for _, rawThread := range rawFlow.ThreadFlows {
					thread := ThreadFlow{
						Steps: make([]FlowStep, 0),
					}

					for _, node := range rawThread.Locations {
						thread.Steps = append(thread.Steps, FlowStep{
							Location: convertSARIFLocation(node.Location, artifactURIs),
							Kinds:    node.Kinds,
						})
					}

					flow.ThreadFlows = append(flow.ThreadFlows, thread)
				}

				finding.CodeFlows = append(finding.CodeFlows, flow)
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}
