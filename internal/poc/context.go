package poc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"devsecops/internal/infra"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v5"
)

type GenerationContext struct {
	CVE         CVE        `json:"cve"`
	Description string     `json:"description"`
	Products    []Product  `json:"products"`
	Materials   []Evidence `json:"materials"`
	Notices     []string   `json:"notices"`
}

func (s *Service) prepare(ctx context.Context, id string) (GenerationContext, error) {
	if !cvePattern.MatchString(id) {
		return GenerationContext{}, errors.New("请输入有效 CVE 编号")
	}
	resolved, err := s.resolve(ctx, id)
	if err != nil {
		return GenerationContext{}, fmt.Errorf("读取 %s 已收集的信息: %w", id, err)
	}
	return s.prepareResolved(ctx, resolved)
}
func (s *Service) prepareResolved(ctx context.Context, resolved lookupResult) (GenerationContext, error) {
	cve := resolved.CVE
	id := cve.ID
	result := GenerationContext{Notices: resolved.Notices, CVE: cve, Description: cve.Manual.Description, Products: []Product{}, Materials: []Evidence{}}
	names := make([]string, 0, len(cve.Sources))
	for name := range cve.Sources {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := cve.Sources[name]
		var source struct {
			Description  string
			URL          string
			Descriptions []struct{ Lang, Value string }
		}
		if err := json.Unmarshal(raw, &source); err != nil {
			return result, err
		}
		if result.Description == "" {
			result.Description = source.Description
			for _, desc := range source.Descriptions {
				if desc.Lang == "en" {
					result.Description = desc.Value
					break
				}
			}
		}
		reference := name + ":" + id
		if source.URL != "" {
			reference = source.URL
		}
		result.Materials = append(result.Materials, Evidence{reference, string(raw)})
	}
	if cve.Manual.Notes != "" {
		result.Materials = append(result.Materials, Evidence{"人工补充:" + id, cve.Manual.Notes})
	}
	rows, err := s.db.Query(ctx, `SELECT profile FROM poc_products ORDER BY key`)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	text := strings.ToLower(result.Description + " " + cve.Manual.Title)
	for rows.Next() {
		var product Product
		if err := rows.Scan(&product); err != nil {
			return result, err
		}
		if product.Name != "" && strings.Contains(text, strings.ToLower(product.Name)) {
			result.Products = append(result.Products, product)
		}
	}
	return result, rows.Err()
}
func (s *Service) currentAgent() *infra.NetAgent {
	s.agentMu.RLock()
	defer s.agentMu.RUnlock()
	return s.agent
}
func (s *Service) agentView() map[string]any {
	agent := s.currentAgent()
	message := ""
	if err := agent.Ready(); err != nil {
		message = err.Error()
	}
	return map[string]any{"protocol": agent.Config.Protocol, "base_url": agent.Config.BaseURL, "model": agent.Config.Model, "has_api_key": agent.Config.APIKey != "", "configuration_error": message, "schema": SpecSchema}
}
func (s *Service) saveAgent(in infra.AgentConfig) error {
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	if in.APIKey == "" {
		if in.BaseURL != s.agent.Config.BaseURL || in.Protocol != s.agent.Config.Protocol {
			return errors.New("更换协议或地址时请重新填写 API Key")
		}
		in.APIKey = s.agent.Config.APIKey
	}
	agent := infra.NewNetAgent(in)
	if err := agent.Ready(); err != nil {
		return err
	}
	values, err := godotenv.Read(".env")
	if err != nil {
		return err
	}
	for key, value := range map[string]string{"AI_PROTOCOL": in.Protocol, "AI_BASE_URL": in.BaseURL, "AI_MODEL": in.Model, "AI_API_KEY": in.APIKey} {
		values[key] = value
	}
	raw, err := godotenv.Marshal(values)
	if err != nil {
		return err
	}
	if err := os.Chmod(".env", 0600); err != nil {
		return err
	}
	if err := os.WriteFile(".env", []byte(raw+"\n"), 0600); err != nil {
		return err
	}
	s.agent = agent
	return nil
}

func (s *Service) registerContext(g *echo.Group) {
	g.GET("/poc-context/:id", func(c *echo.Context) error {
		result, err := s.prepare(c.Request().Context(), strings.ToUpper(strings.TrimSpace(c.Param("id"))))
		return respond(c, result, err)
	})
	g.POST("/poc-context/:id/refresh", func(c *echo.Context) error {
		resolved, err := s.refreshCVE(c.Request().Context(), strings.ToUpper(strings.TrimSpace(c.Param("id"))))
		if err != nil {
			return respond(c, nil, err)
		}
		result, err := s.prepareResolved(c.Request().Context(), resolved)
		return respond(c, result, err)
	})
	g.PUT("/poc-agent", func(c *echo.Context) error {
		var in struct {
			Protocol string `json:"protocol"`
			BaseURL  string `json:"base_url"`
			Model    string `json:"model"`
			APIKey   string `json:"api_key"`
		}
		if err := decode(c, &in); err != nil {
			return respond(c, nil, err)
		}
		if err := s.saveAgent(infra.AgentConfig{Protocol: strings.TrimSpace(in.Protocol), BaseURL: strings.TrimRight(strings.TrimSpace(in.BaseURL), "/"), Model: strings.TrimSpace(in.Model), APIKey: strings.TrimSpace(in.APIKey)}); err != nil {
			return respond(c, nil, err)
		}
		return c.JSON(200, s.agentView())
	})
}
