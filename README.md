# geoip-policyd

## About

Postfix-Submission policy server that checks sender IPs and blocks senders, if they come from too many countries or if 
they come from too many IP addresses.

## Whitelist

You can specify a whitelist, which must be valid JSON. The format is:

```json
{
  "data": [
    {
      "comment": "Whatever comment you like...",
      "sender": "localpart@domain.tld",
      "ips": NUMBER,
      "countries": NUMBER
    },
    ...
  ]
}
```

It is possible to only specify *ips* or *countries*. The missing parameter will be set to its default. Furthermore, the
data structure is read one by one and the rules are evaluated as first match wins. By redefining a sender more than
once, only the first will be used.

The simplest way to use the program is by using a docker image. You can build your own, as the default repository is not
public for other people.

```shell
cd /path/to/Dockerfile
docker build -t geoip-policyd:latest .
```

You need to change the docker-compose.yml file as well. If you prefer, you can add a Redis
service and run the *geoip-policyd* container in bridged mode.

As this is my first Go project. Feel free to help me to make it better ;-)

The service is configured in Postfix like this:

## Postfix integration

```
smtpd_recipient_restrictions =
    ...
    check_policy_service inet:127.0.0.1:46464
    ...
```

if you use the docker-compose.yml file as provided.

## Server options

```shell
geoip-policyd server --help
```

produces the following output:

```
usage: geoip-policyd server [-h|--help] [-a|--server-address "<value>"]
                     [-p|--server-port <integer>] [-A|--redis-address
                     "<value>"] [-P|--redis-port <integer>]
                     [--redis-database-number <integer>] [--redis-username
                     "<value>"] [--redis-password "<value>"]
                     [--redis-writer-address "<value>"] [--redis-writer-port
                     <integer>] [--redis-writer-database-number <integer>]
                     [--redis-writer-username "<value>"]
                     [--redis-writer-password "<value>"] [--redis-prefix
                     "<value>"] [--redis-ttl <integer>] [-g|--geoip-path
                     "<value>"] [--max-countries <integer>] [--max-ips
                     <integer>] [-w|--whitelist-path "<value>"] [-v|--verbose]
                     [--version]

                     Run a geoip policy server

Arguments:

  -h  --help                          Print help information
  -a  --server-address                IPv4 or IPv6 address for the policy service; default(127.0.0.1)
      --http-address                  HTTP address for incoming requests; default(:8080)
  -p  --server-port                   Port for the policy service; default(4646)
  -A  --redis-address                 IPv4 or IPv6 address for the Redis service; default(127.0.0.1)
  -P  --redis-port                    Port for the Redis service; default(6379)
      --redis-database-number         Redis database number
      --redis-username                Redis username
      --redis-password                Redis password
      --redis-writer-address          IPv4 or IPv6 address for a Redis service (writer)
      --redis-writer-port             Port for a Redis service (writer)
      --redis-writer-database-number  Redis database number (writer)
      --redis-writer-username         Redis username (writer)
      --redis-writer-password         Redis password (writer)
      --redis-prefix                  Redis prefix; default(geopol_)
      --redis-ttl                     Redis TTL; default(3600)
  -g  --geoip-path                    Full path to the GeoIP database file; default(/usr/share/GeoIP/GeoLite2-City.mmdb)
      --max-countries                 Maximum number of countries before rejecting e-mails; default(3)
      --max-ips                       Maximum number of IP addresses before rejecting e-mails; default(10)
  -w  --whitelist-path                Whitelist with different IP and country limits
  -v  --verbose                       Verbose mode
      --version                       Current version

```

## Reload options

```shell
geoip-policyd reload --help
```

produces the following output:

```
usage: geoip-policyd reload [-h|--help] [--http-uri "<value>"] [-v|--verbose]
                     [--version]

                     Reload the geoip-policyd server

Arguments:

  -h  --help      Print help information
      --http-uri  HTTP URI to the REST server; default(http://127.0.0.1:8080)
  -v  --verbose   Verbose mode
      --version   Current version

```

## Environment variables

The following environment variables can be used to configure the policy service. This is especially useful, if you plan
on running the service as a docker service.

### Server

Variable | Description
---|---
SERVER_ADDRESS | IPv4 or IPv6 address for the policy service; default(127.0.0.1)
SERVER_PORT | Port for the policy service; default(4646)
HTTP_ADDRESS | HTTP address for incoming requests; default(:8080)
REDIS_ADDRESS | IPv4 or IPv6 address for the Redis service; default(127.0.0.1)
REDIS_PORT | Port for the Redis service; default(6379)
REDIS_DATABASE_NUMBER | Redis database number
REDIS_USERNAME | Redis username
REDIS_PASSWORD | Redis password
REDIS_WRITER_ADDRESS | IPv4 or IPv6 address for a Redis service (writer)
REDIS_WRITER_PORT | Port for a Redis service (writer)
REDIS_WRITER_DATABASE_NUMBER | Redis database number (writer)
REDIS_WRITER_USERNAME | Redis username (writer)
REDIS_WRITER_PASSWORD | Redis password (writer)
REDIS_PREFIX | Redis prefix; default(geopol_)
REDIS_TTL | Redis TTL; default(3600)
GEOIP_PATH | Full path to the GeoIP database file; default(/usr/share/GeoIP/GeoLite2-City.mmdb)
MAX_COUNTRIES | Maximum number of countries before rejecting e-mails; default(3)
MAX_IPS | Maximum number of IP addresses before rejecting e-mails; default(10)
WHITELIST_PATH | Whitelist with different IP and country limits

### Reload

Variable | Description
---|---
HTTP_URI | http://127.0.0.1:8080
