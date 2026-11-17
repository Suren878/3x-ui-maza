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
	m.POST("/initialize", func(c *gin.Context) { jsonMsg(c, "", s.Initialize(session.GetLoginUser(c).Id)) })
	m.POST("/settings", func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2048)
		var req struct {
			Remark  *string `json:"remark"`
			Enabled *bool   `json:"enabled"`
		}
		if c.ShouldBindJSON(&req) != nil || (req.Remark == nil && req.Enabled == nil) {
			c.JSON(400, gin.H{"success": false, "msg": "Invalid request"})
			return
		}
		jsonMsg(c, "", s.Configure(session.GetLoginUser(c).Id, req.Remark, req.Enabled))
	})
	m.POST("/remove", func(c *gin.Context) { jsonMsg(c, "", s.Remove(session.GetLoginUser(c).Id)) })
	m.POST("/clients", func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2048)
		var req struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		if c.ShouldBindJSON(&req) != nil {
			c.JSON(400, gin.H{"success": false, "msg": "Invalid request"})
			return
		}
		if err := s.QueueClient(session.GetLoginUser(c).Id, req.Name, req.Email); err != nil {
			jsonMsg(c, "", err)
			return
		}
		c.JSON(http.StatusAccepted, gin.H{"success": true, "obj": gin.H{"pending": true}})
	})
	m.POST("/clients/:id/enable", func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 512)
		var req struct {
			Enabled *bool `json:"enabled"`
		}
		if c.ShouldBindJSON(&req) != nil || req.Enabled == nil {
			c.JSON(400, gin.H{"success": false, "msg": "Invalid request"})
			return
		}
		jsonMsg(c, "", s.SetClientEnabled(session.GetLoginUser(c).Id, c.Param("id"), *req.Enabled))
	})
	m.GET("/by-email/:email/share", func(c *gin.Context) {
		id, link, e := s.ExportByEmail(session.GetLoginUser(c).Id, c.Param("email"))
		jsonObj(c, gin.H{"id": id, "link": link}, e)
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
