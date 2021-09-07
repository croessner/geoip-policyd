package main

import (
	"fmt"
	"github.com/gomodule/redigo/redis"
	"log"
)

func newRedisPool() *redis.Pool {
	return &redis.Pool{
		MaxIdle:   80,
		MaxActive: 1000, // max number of connections
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial(
				"tcp", fmt.Sprintf("%s:%d", cfg.RedisAddress, cfg.RedisPort),
				redis.DialDatabase(cfg.RedisDB),
				redis.DialUsername(cfg.RedisUsername),
				redis.DialPassword(cfg.RedisPassword),
			)
			if err != nil {
				log.Panic("Panic: Can't create Redis pool", err)
			}

			return c, err
		},
	}
}

var redisPool = newRedisPool()
