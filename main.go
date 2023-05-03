package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/gin-gonic/gin"
	"github.com/pion/stun"
)

type Config struct {
	PrefixList []string `json:"prefix_list"`
	Port       int      `json:"port"`
	Token      string   `json:"token"`
}

type Response struct {
	Status     int      `json:"status"`
	Message    string   `json:"message"`
	Timestamp  int64    `json:"timestamp,omitempty"`
	PrefixList []string `json:"prefix_list,omitempty"`
	// Data      Data   `json:"data"`
}

var (
	config      Config
	ipBlacklist *ristretto.Cache
	localIPList map[string]bool
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

	localIPList = make(map[string]bool)

	// Load local ip list
	for _, prefix := range config.PrefixList {
		ips, err := SplitSubnet(prefix)
		if err == nil {
			for _, ip := range ips {
				localIPList[ip] = true
			}
		}
	}

	f, _ := os.OpenFile("./backend.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	defer f.Close()
	gin.DefaultWriter = f
	gin.ForceConsoleColor()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(BearTokenAuthMiddleware())
	r.Use(RateLimitingMiddleware())
	r.POST("/bind", func(ctx *gin.Context) {
		jsonData, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			ctx.JSON(400, Response{
				Status:  400,
				Message: "Fail to read request body.",
			})
			return
		}
		data := make(map[string]interface{})
		err = json.Unmarshal(jsonData, &data)
		if err != nil {
			ctx.JSON(400, Response{
				Status:  400,
				Message: "Bad format.",
			})
			return
		}
		addr, ok := data["target_addr"].(string)
		if !ok {
			ctx.JSON(400, Response{
				Status:  400,
				Message: "Target address must be specified.",
			})
			return
		}

		ip, ok := data["proxy_ip"].(string)
		if !ok {
			ctx.JSON(400, Response{
				Status:  400,
				Message: "Local IP address must be specified.",
			})
			return
		}

		_, ok = localIPList[ip]
		if !ok {
			ctx.JSON(400, Response{
				Status:  400,
				Message: "IP address is not valid",
			})
			return
		}

		c, err := stun.Dial(&net.UDPAddr{
			IP: net.ParseIP(ip),
		}, "udp4", addr)
		
		if err != nil {
			ctx.JSON(500, Response{
				Status:  500,
				Message: "Fail to dial the target address.",
			})
			return
		}
		err = c.Do(stun.MustBuild(stun.TransactionID, stun.BindingRequest), func(res stun.Event) {
			if res.Error == nil {
				ctx.JSON(200, Response{
					Status:    200,
					Message:   res.Message.String(),
					Timestamp: time.Now().Unix(),
				})
			} else {
				ctx.JSON(500, Response{
					Status:  500,
					Message: res.Error.Error(),
				})
			}
		})
		if err != nil {
			// Handle error
		}
		if err := c.Close(); err != nil {
			// Handle error
		}
	})
	r.GET("/view", func(ctx *gin.Context) {
		ctx.JSON(200, Response{
			Status:     200,
			PrefixList: config.PrefixList,
			Timestamp:  time.Now().Unix(),
		})
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
