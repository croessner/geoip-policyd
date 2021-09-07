package main

import (
	"fmt"
	"github.com/gomodule/redigo/redis"
	"log"
)

func newRedisPool(
		redisAddress string, redisPort int, redisDB int, redisUsername string, redisPassword string) *redis.Pool {
	return &redis.Pool{
		MaxIdle:   80,
		MaxActive: 1000, // max number of connections
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial(
				"tcp", fmt.Sprintf("%s:%d", redisAddress, redisPort),
				redis.DialDatabase(redisDB),
				redis.DialUsername(redisUsername),
				redis.DialPassword(redisPassword),
			)
			if err != nil {
				log.Panic("Panic: Can't create Redis pool", err)
			}

			return c, err
		},
	}
}
