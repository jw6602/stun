package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/gin-gonic/gin"
)

type Config struct {
	PrefixList []string `json:"prefix_list"`
	Port       int      `json:"port"`
	Token      string   `json:"token"`
}

var (
	config      Config
	ipBlacklist *ristretto.Cache
)

func main() {
	// Load config
	raw, err := ioutil.ReadFile("./config.json")
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(raw, &config)
	if err != nil {
		panic(err)
	}
	f, _ := os.OpenFile("./backend.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	defer f.Close()
	gin.DefaultWriter = f
	gin.ForceConsoleColor()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(BearTokenAuthMiddleware())
	r.Use(RateLimitingMiddleware())
	r.POST("/submit", func(ctx *gin.Context) {
		
	})
	r.Run(fmt.Sprintf(":%v", config.Port))
}

func BearTokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !c.GetBool("authorized") {
			bearToken := c.Request.Header.Get("Authorization")
			if strings.HasPrefix(bearToken, "Bearer ") && bearToken[7:] == config.Token {
				c.Set("authorized", true)
			}
		}
		c.Next()
	}
}

func RateLimitingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !c.GetBool("authorized") {
			count, ok := ipBlacklist.Get(c.Request.RemoteAddr)
			if !ok {
				count = 0
			}
			if count.(int) > 10 {
				c.AbortWithStatus(403)
				return
			}
			ipBlacklist.SetWithTTL(c.Request.RemoteAddr, count.(int)+1, 1, time.Hour)
			c.AbortWithStatus(401)
			return
		}
		c.Next()
	}
}
