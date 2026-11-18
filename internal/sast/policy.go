package sast

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
)

type QueryRule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Language string `json:"language"`
	Code     string `json:"code"`
}

type QuerySuite struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Rules []string `json:"rules"`
}

type Policy struct {
	Active string       `json:"active"`
	Rules  []QueryRule  `json:"rules"`
	Suites []QuerySuite `json:"suites"`
}

func (p Policy) validate() error {
	rules := map[string]bool{}
	for _, r := range p.Rules {
		if r.ID == "" || rules[r.ID] || strings.TrimSpace(r.Name) == "" || strings.TrimSpace(r.Code) == "" {
			return errors.New("规则需要唯一标识、名称和 QL 正文")
		}
		switch r.Language {
		case "go", "java", "javascript", "python":
		default:
			return fmt.Errorf("规则语言不受支持：%s", r.Language)
		}
		rules[r.ID] = true
	}
	suites := map[string]bool{"code-scanning": true, "security-extended": true}
	for _, suite := range p.Suites {
		if suite.ID == "" || suites[suite.ID] || strings.TrimSpace(suite.Name) == "" || len(suite.Rules) == 0 {
			return errors.New("自定义套件需要唯一标识、名称和至少一条规则")
		}
		suites[suite.ID] = true
		seen := map[string]bool{}
		for _, id := range suite.Rules {
			if !rules[id] || seen[id] { return fmt.Errorf("套件 %s 引用了无效或重复的规则 %s", suite.Name, id) }
			seen[id] = true
		}
	}
	if !suites[p.Active] { return errors.New("请选择有效的生效套件") }
	return nil
}

func (s *Store) InitPolicy(ctx context.Context, active string) error {
	if _, err := s.db.Exec(ctx, `CREATE TABLE IF NOT EXISTS sast_policy (
		id integer PRIMARY KEY CHECK (id=1), revision bigint NOT NULL, policy jsonb NOT NULL)`); err != nil {
		return err
	}
	initial := Policy{Active: active, Rules: []QueryRule{}, Suites: []QuerySuite{}}
	if err := initial.validate(); err != nil { return err }
	_, err := s.db.Exec(ctx, `INSERT INTO sast_policy VALUES (1,1,$1) ON CONFLICT (id) DO NOTHING`, initial)
	return err
}

func (s *Store) policy(ctx context.Context) (Policy, int64, error) {
	var p Policy
	var revision int64
	err := s.db.QueryRow(ctx, `SELECT policy,revision FROM sast_policy WHERE id=1`).Scan(&p, &revision)
	return p, revision, err
}

func (h *Handler) GetPolicy(c *echo.Context) error {
	p, revision, err := h.service.store.policy(c.Request().Context())
	if err != nil { return err }
	return c.JSON(http.StatusOK, map[string]any{"policy": p, "revision": revision})
}

func (h *Handler) PutPolicy(c *echo.Context) error {
	var req struct {
		Policy Policy `json:"policy"`
		Revision int64 `json:"revision"`
	}
	if err := c.Bind(&req); err != nil { return err }
	if err := req.Policy.validate(); err != nil { return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()}) }
	tag, err := h.service.store.db.Exec(c.Request().Context(), `UPDATE sast_policy SET policy=$1,revision=revision+1 WHERE id=1 AND revision=$2`, req.Policy, req.Revision)
	if err != nil { return err }
	if tag.RowsAffected() == 0 { return c.JSON(http.StatusConflict, map[string]string{"error": "配置已被其他人修改，请重新加载"}) }
	return c.JSON(http.StatusOK, map[string]int64{"revision": req.Revision + 1})
}
