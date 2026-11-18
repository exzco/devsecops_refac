package poc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"devsecops/internal/infra"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v5"
)

func decode(c *echo.Context, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 2<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func respond(c *echo.Context, data any, err error) error {
	if err != nil {
		return c.JSON(400, map[string]string{"error": err.Error()})
	}
	return c.JSON(200, data)
}

func (s *Service) Register(g *echo.Group) {
	g.GET("/pocs", func(c *echo.Context) error {
		limit := 200
		if l := c.QueryParam("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
				limit = n
			}
		}
		f := CVEFilter{
			Query:  strings.TrimSpace(c.QueryParam("q")),
			Source: strings.TrimSpace(c.QueryParam("source")),
			Year:   strings.TrimSpace(c.QueryParam("year")),
			Start:  strings.TrimSpace(c.QueryParam("start")),
			End:    strings.TrimSpace(c.QueryParam("end")),
			Limit:  limit,
		}
		items, err := s.list(c.Request().Context(), f)
		if err != nil {
			return respond(c, nil, err)
		}
		return c.JSON(200, items)
	})
	g.PUT("/pocs/:id", func(c *echo.Context) error {
		id := strings.ToUpper(c.Param("id"))
		if !ValidCVE(id) {
			return respond(c, nil, errors.New("invalid CVE ID"))
		}
		var in Manual
		if err := decode(c, &in); err != nil {
			return respond(c, nil, err)
		}
		for _, link := range in.PoCs {
			u, err := url.Parse(link.URL)
			if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
				return respond(c, nil, errors.New("PoC links must use HTTP(S)"))
			}
		}
		if err := s.lookupNuclei(c.Request().Context(), id); err != nil {
			return respond(c, nil, err)
		}
		_, err := s.db.Exec(c.Request().Context(), `INSERT INTO poc_cves(id,sources,manual) VALUES($1,'{}',$2) ON CONFLICT(id) DO UPDATE SET manual=EXCLUDED.manual,updated_at=now()`, id, in)
		if err == nil {
			s.invalidate(c.Request().Context(), id)
		}
		return respond(c, in, err)
	})
	g.POST("/pocs/sync", func(c *echo.Context) error {
		var in SyncInput
		if err := decode(c, &in); err != nil {
			return respond(c, nil, err)
		}
		if _, _, err := in.Dates(); err != nil {
			return respond(c, nil, err)
		}
		id, err := s.enqueue(c.Request().Context(), "sync", in)
		return respond(c, id, err)
	})
	g.POST("/pocs/search", func(c *echo.Context) error {
		var in struct {
			IDs []string `json:"ids"`
		}
		if err := decode(c, &in); err != nil {
			return respond(c, nil, err)
		}
		if len(in.IDs) == 0 || len(in.IDs) > 100 {
			return respond(c, nil, errors.New("选择 1–100 个 CVE"))
		}
		id, err := s.enqueue(c.Request().Context(), "search", in)
		return respond(c, id, err)
	})
	g.GET("/poc-jobs", func(c *echo.Context) error {
		rows, err := s.db.Query(c.Request().Context(), `SELECT json_build_object('id',id,'kind',kind,'status',status,'progress',progress,'error',error,'created_at',created_at) FROM poc_jobs ORDER BY id DESC LIMIT 30`)
		if err != nil {
			return respond(c, nil, err)
		}
		data, err := pgx.CollectRows(rows, pgx.RowTo[json.RawMessage])
		return respond(c, data, err)
	})
	s.registerNuclei(g)
	s.registerAgent(g)
}

func (s *Service) registerAgent(g *echo.Group) {
	s.registerContext(g)
	g.GET("/poc-agent", func(c *echo.Context) error { return c.JSON(200, s.agentView()) })
	g.GET("/poc-products", func(c *echo.Context) error {
		items, err := s.products(c.Request().Context())
		return respond(c, items, err)
	})
	g.PUT("/poc-products/:key", func(c *echo.Context) error {
		var in Product
		if err := decode(c, &in); err != nil {
			return respond(c, nil, err)
		}
		if in.Key != c.Param("key") || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`).MatchString(in.Key) || in.Name == "" {
			return respond(c, nil, errors.New("产品标识须为小写字母、数字和连字符，名称不能为空"))
		}
		_, err := s.db.Exec(c.Request().Context(), `INSERT INTO poc_products(key,profile) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET profile=EXCLUDED.profile,updated_at=now()`, in.Key, in)
		return respond(c, in, err)
	})
	g.POST("/poc-generate", func(c *echo.Context) error {
		var in GenerateInput
		if err := decode(c, &in); err != nil {
			return respond(c, nil, err)
		}
		if len(in.IDs) == 0 || len(in.IDs) > 20 {
			return respond(c, nil, errors.New("指定 1–20 个 CVE 编号"))
		}
		for i, id := range in.IDs {
			in.IDs[i] = strings.ToUpper(strings.TrimSpace(id))
			if _, err := s.get(c.Request().Context(), in.IDs[i]); err != nil {
				return respond(c, nil, fmt.Errorf("%s 尚未收集，请先同步", id))
			}
		}
		ctx := c.Request().Context()
		tx, err := s.db.Begin(ctx)
		if err != nil {
			return respond(c, nil, err)
		}
		defer tx.Rollback(ctx)
		jobIDs := make([]int64, 0, len(in.IDs))
		for _, cveID := range in.IDs {
			var jobID int64
			if err := tx.QueryRow(ctx, `INSERT INTO poc_jobs(kind,input,progress) VALUES('generate',$1,$2) RETURNING id`, GenerateInput{IDs: []string{cveID}}, cveID).Scan(&jobID); err != nil {
				return respond(c, nil, err)
			}
			jobIDs = append(jobIDs, jobID)
		}
		return respond(c, jobIDs, tx.Commit(ctx))
	})
	g.GET("/poc-generations", func(c *echo.Context) error {
		rows, err := s.db.Query(c.Request().Context(), `SELECT id,cve_id,spec,template,created_at FROM poc_generations ORDER BY id DESC LIMIT 200`)
		if err != nil {
			return respond(c, nil, err)
		}
		defer rows.Close()
		items := []Generation{}
		for rows.Next() {
			var item Generation
			var raw json.RawMessage
			var oldTemplate string
			if err := rows.Scan(&item.ID, &item.CVEID, &raw, &oldTemplate, &item.CreatedAt); err != nil {
				return respond(c, nil, err)
			}
			spec, err := readGenerationSpec(raw, oldTemplate)
			if err != nil {
				return respond(c, nil, err)
			}
			item.Spec = spec
			item.Templates, err = Render(item.CVEID, spec)
			if err != nil {
				return respond(c, nil, fmt.Errorf("生成记录 %d: %w", item.ID, err))
			}
			items = append(items, item)
		}
		return respond(c, items, rows.Err())
	})
	g.PUT("/poc-generations/:id", func(c *echo.Context) error {
		var spec Spec
		if err := decode(c, &spec); err != nil {
			return respond(c, nil, err)
		}
		var id int64
		var cveID string
		if err := s.db.QueryRow(c.Request().Context(), `SELECT id,cve_id FROM poc_generations WHERE id=$1`, c.Param("id")).Scan(&id, &cveID); err != nil {
			return respond(c, nil, err)
		}
		result, err := s.saveGeneration(c.Request().Context(), cveID, spec, id)
		return respond(c, result, err)
	})
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

func (s *Service) registerNuclei(g *echo.Group) {
	g.GET("/pocs/:id/nuclei", func(c *echo.Context) error {
		cve, err := s.get(c.Request().Context(), strings.ToUpper(c.Param("id")))
		if err != nil {
			return respond(c, nil, err)
		}
		materials, err := storedNuclei(cve)
		return respond(c, materials, err)
	})
}
