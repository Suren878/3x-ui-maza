package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/web/session"
	"net/http"
)

// Registered inside the panel's login + CSRF middleware, never the public API.
func registerMaza(g *gin.RouterGroup) {
	s, err := service.OpenMazaService()
	if err != nil {
		logger.Error("MAZA initialization failed: ", err)
	}
	m := g.Group("/maza/api")
	m.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("X-Content-Type-Options", "nosniff")
		if s == nil {
			c.AbortWithStatusJSON(503, gin.H{"success": false, "msg": "MAZA is not configured"})
		}
	})
	m.GET("/clients", func(c *gin.Context) { v, e := s.List(session.GetLoginUser(c).Id); jsonObj(c, v, e) })
	m.POST("/clients", func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2048)
		var req struct {
			Name string `json:"name"`
		}
		if c.ShouldBindJSON(&req) != nil {
			c.JSON(400, gin.H{"success": false, "msg": "Invalid request"})
			return
		}
		jsonMsg(c, "", s.Create(session.GetLoginUser(c).Id, req.Name))
	})
	m.POST("/clients/:id/delete", func(c *gin.Context) { jsonMsg(c, "", s.Delete(session.GetLoginUser(c).Id, c.Param("id"))) })
	m.GET("/clients/:id/share", func(c *gin.Context) {
		link, _, e := s.Export(session.GetLoginUser(c).Id, c.Param("id"))
		jsonObj(c, gin.H{"link": link}, e)
	})
	m.GET("/clients/:id/bundle", func(c *gin.Context) {
		_, bundle, e := s.Export(session.GetLoginUser(c).Id, c.Param("id"))
		if e != nil {
			jsonObj(c, nil, e)
			return
		}
		c.Header("Content-Disposition", `attachment; filename="maza-client.zip"`)
		c.Data(200, "application/zip", bundle)
	})
}
