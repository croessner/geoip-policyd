/*
geoip-policyd
Copyright (C) 2021  Rößner-Network-Solutions

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
