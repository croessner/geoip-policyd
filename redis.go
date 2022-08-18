package main

import (
	"fmt"
	"time"

	"github.com/go-kit/log/level"
	"github.com/gomodule/redigo/redis"
)

type RedisPool interface {
	NewReadConn() redis.Conn
	NewWriteConn() redis.Conn
}

type redisPool struct {
	readPool  *redis.Pool
	writePool *redis.Pool
}

func (r *redisPool) initReaderPool() {
	r.readPool = newRedisPool(
		config.RedisProtocol.Get(),
		config.RedisAddress,
		config.RedisPort,
		config.RedisDB,
		config.RedisUsername,
		config.RedisPassword,
	)
}

func (r *redisPool) initWriterPool() {
	if !(config.RedisProtocol.Get() == config.RedisProtocolW.Get() &&
		config.RedisAddress == config.RedisAddressW &&
		config.RedisPort == config.RedisPortW) {
		r.writePool = newRedisPool(
			config.RedisProtocolW.Get(),
			config.RedisAddressW,
			config.RedisPortW,
			config.RedisDBW,
			config.RedisUsernameW,
			config.RedisPasswordW,
		)
	} else {
		r.writePool = r.readPool
	}
}

func (r *redisPool) NewReadConn() redis.Conn { //nolint:ireturn // This is the expected behavior
	level.Debug(logger).Log("msg", "Get new redis connection")

	return r.readPool.Get()
}

func (r *redisPool) NewWriteConn() redis.Conn { //nolint:ireturn // This is the expected behavior
	level.Debug(logger).Log("msg", "Get new redis connection")

	return r.writePool.Get()
}

func newRedisPool(
	redisProtocol string, redisAddress string, redisPort int, redisDB int, redisUsername string, redisPassword string,
) *redis.Pool {
	return &redis.Pool{
		MaxIdle:   5,   //nolint:gomnd // Max idle connections
		MaxActive: 100, //nolint:gomnd // Max number of connections
		Wait:      true,
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			if time.Since(t) < time.Minute {
				return nil
			}

			_, err := c.Do("PING")

			return err
		},
		IdleTimeout: 5 * time.Minute, //nolint:gomnd // Time factor
		Dial: func() (redis.Conn, error) {
			var conn string

			switch redisProtocol {
			case "tcp", "tcp6":
				conn = fmt.Sprintf("%s:%d", redisAddress, redisPort)
			case "unix":
				conn = redisAddress
			default:
				level.Error(logger).Log("error", "Unsupported protocol")
			}

			redisConn, err := redis.Dial(
				redisProtocol, conn,
				redis.DialDatabase(redisDB),
				redis.DialUsername(redisUsername),
				redis.DialPassword(redisPassword),
			)

			if err != nil {
				level.Error(logger).Log("error", err.Error())
			} else {
				level.Debug(logger).Log("msg", "New redis connection established")
			}

			return redisConn, err
		},
	}
}

func NewRedisPool() RedisPool { //nolint:ireturn // This is the expected behavior
	r := &redisPool{}

	r.initReaderPool()
	r.initWriterPool()

	return r
}
