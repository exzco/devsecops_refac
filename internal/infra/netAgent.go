package infra

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

type AgentConfig struct{ Protocol, BaseURL, Model, APIKey string }
type NetAgent struct {
	Config AgentConfig
	Client *http.Client
}

func NewNetAgent(cfg AgentConfig) *NetAgent {
	return &NetAgent{cfg, &http.Client{Timeout: 120 * time.Second}}
}
func (a *NetAgent) Ready() error {
	if a.Config.APIKey == "" || a.Config.Model == "" {
		return fmt.Errorf("AI_API_KEY and AI_MODEL are required")
	}
	u, err := url.Parse(a.Config.BaseURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("AI_BASE_URL must be an HTTP(S) URL")
	}
	officialPaths := map[string][]string{
		"openai@api.openai.com":                    {"/v1"},
		"anthropic@api.anthropic.com":              {"/v1"},
		"gemini@generativelanguage.googleapis.com": {"/v1", "/v1beta"},
	}
	if paths, ok := officialPaths[a.Config.Protocol+"@"+u.Host]; ok && !slices.Contains(paths, strings.TrimRight(u.Path, "/")) {
		return fmt.Errorf("API Base URL 路径应为 %s，不能填写具体接口路径", strings.Join(paths, " 或 "))
	}
	switch a.Config.Protocol {
	case "openai", "anthropic", "gemini":
		return nil
	}
	return fmt.Errorf("AI_PROTOCOL must be openai, anthropic or gemini")
}
func (a *NetAgent) Extract(ctx context.Context, system, input string, schema json.RawMessage) (json.RawMessage, error) {
	if err := a.Ready(); err != nil {
		return nil, err
	}
	cfg := a.Config
	var compactSchema bytes.Buffer
	if err := json.Compact(&compactSchema, schema); err != nil {
		return nil, err
	}
	schema = compactSchema.Bytes()
	endpoint := strings.TrimRight(cfg.BaseURL, "/")
	var body any
	headers := map[string]string{"Content-Type": "application/json"}
	switch cfg.Protocol {
	case "openai":
		endpoint += "/chat/completions"
		headers["Authorization"] = "Bearer " + cfg.APIKey
		body = map[string]any{"model": cfg.Model, "messages": []any{map[string]string{"role": "system", "content": system + "\nJSON Schema:\n" + string(schema)}, map[string]string{"role": "user", "content": input}}, "response_format": map[string]string{"type": "json_object"}}
	case "anthropic":
		endpoint += "/messages"
		headers["x-api-key"] = cfg.APIKey
		headers["anthropic-version"] = "2023-06-01"
		body = map[string]any{"model": cfg.Model, "max_tokens": 8192, "system": system + "\nJSON Schema:\n" + string(schema), "messages": []any{map[string]string{"role": "user", "content": input}}}
	case "gemini":
		endpoint += "/models/" + url.PathEscape(cfg.Model) + ":generateContent"
		headers["x-goog-api-key"] = cfg.APIKey
		body = map[string]any{"systemInstruction": map[string]any{"parts": []any{map[string]string{"text": system + "\nJSON Schema:\n" + string(schema)}}}, "contents": []any{map[string]any{"role": "user", "parts": []any{map[string]string{"text": input}}}}, "generationConfig": map[string]any{"responseMimeType": "application/json"}}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AI request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("AI %s returned HTTP %d", cfg.Protocol, resp.StatusCode)
	}
	var result struct {
		ID string `json:"id"`
		ResponseID string `json:"responseId"`
		Usage json.RawMessage `json:"usage"`
		UsageMetadata json.RawMessage `json:"usageMetadata"`
		Choices []struct {
			Message      struct{ Content string }
			FinishReason string `json:"finish_reason"`
		}
		Content    []struct{ Type, Text string }
		StopReason string `json:"stop_reason"`
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text    string
					Thought bool
				}
			}
			FinishReason string
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	slog.InfoContext(ctx, "AI token usage", "protocol", cfg.Protocol, "model", cfg.Model, "request_id", result.ID, "response_id", result.ResponseID, "system_chars", utf8.RuneCountInString(system)+utf8.RuneCount(schema), "input_chars", utf8.RuneCountInString(input), "usage", string(result.Usage), "usage_metadata", string(result.UsageMetadata))
	var output string
	switch cfg.Protocol {
	case "openai":
		if len(result.Choices) != 1 || result.Choices[0].FinishReason != "stop" {
			return nil, fmt.Errorf("AI response incomplete or refused")
		}
		output = result.Choices[0].Message.Content
	case "anthropic":
		if result.StopReason != "end_turn" {
			return nil, fmt.Errorf("AI response incomplete: %s", result.StopReason)
		}
		for _, p := range result.Content {
			if p.Type == "text" {
				output += p.Text
			}
		}
	case "gemini":
		if len(result.Candidates) != 1 || result.Candidates[0].FinishReason != "STOP" {
			return nil, fmt.Errorf("AI response incomplete or refused")
		}
		for _, p := range result.Candidates[0].Content.Parts {
			if !p.Thought {
				output += p.Text
			}
		}
	}
	if !json.Valid([]byte(output)) {
		return nil, fmt.Errorf("AI response is not JSON")
	}
	return json.RawMessage(output), nil
}
