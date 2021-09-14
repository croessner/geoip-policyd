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
                     [-p|--server-port <integer>] [--http-address "<value>"]
                     [-A|--redis-address "<value>"] [-P|--redis-port <integer>]
                     [--redis-database-number <integer>] [--redis-username
                     "<value>"] [--redis-password "<value>"]
                     [--redis-writer-address "<value>"] [--redis-writer-port
                     <integer>] [--redis-writer-database-number <integer>]
                     [--redis-writer-username "<value>"]
                     [--redis-writer-password "<value>"] [--redis-prefix
                     "<value>"] [--redis-ttl <integer>] [-g|--geoip-path
                     "<value>"] [--max-countries <integer>] [--max-ips
                     <integer>] [-w|--whitelist-path "<value>"] [--use-ldap]
                     [--ldap-server-uri "<value>" [--ldap-server-uri "<value>" ...]]
                     [--ldap-basedn "<value>"] [--ldap-binddn "<value>"]
                     [--ldap-bindpw-path "<value>"] [--ldap-filter "<value>"]
                     [--ldap-result-attribute "<value>"] [--ldap-starttls]
                     [--ldap-tls-cafile "<value>"] [--ldap-tls-client-cert
                     "<value>"] [--ldap-tls-client-key "<value>"]
                     [--ldap-sasl-external] [--ldap-scope "<value>"]
                     [-v|--verbose] [--version]

                     Run a geoip policy server

Arguments:

  -h  --help                          Print help information
  -a  --server-address                IPv4 or IPv6 address for the policy service. Default: 127.0.0.1
  -p  --server-port                   Port for the policy service. Default: 4646
      --http-address                  HTTP address for incoming requests. Default: :8080
  -A  --redis-address                 IPv4 or IPv6 address for the Redis service. Default: 127.0.0.1
  -P  --redis-port                    Port for the Redis service. Default: 6379
      --redis-database-number         Redis database number. Default: 0
      --redis-username                Redis username. Default:
      --redis-password                Redis password. Default:
      --redis-writer-address          IPv4 or IPv6 address for a Redis service (writer). Default: 127.0.0.1
      --redis-writer-port             Port for a Redis service (writer). Default: 6379
      --redis-writer-database-number  Redis database number (writer). Default: 0
      --redis-writer-username         Redis username (writer). Default:
      --redis-writer-password         Redis password (writer). Default:
      --redis-prefix                  Redis prefix. Default: geopol_
      --redis-ttl                     Redis TTL in seconds. Default: 3600
  -g  --geoip-path                    Full path to the GeoIP database file. Default: /usr/share/GeoIP/GeoLite2-City.mmdb
      --max-countries                 Maximum number of countries before rejecting e-mails. Default: 3
      --max-ips                       Maximum number of IP addresses before rejecting e-mails. Default: 10
  -w  --whitelist-path                Whitelist with different IP and country limits. Default:
      --use-ldap                      Enable LDAP support. Default: false
      --ldap-server-uri               Server URI. Specify multiple times, if you need more than one server. Default: [ldap://127.0.0.1:389/]
      --ldap-basedn                   Base DN. Default:
      --ldap-binddn                   Bind DN. Default:
      --ldap-bindpw-path              File containing the LDAP users password. Default:
      --ldap-filter                   Filter with %s placeholder. Default: (&(objectClass=*)(mailAlias=%s))
      --ldap-result-attribute         Result attribute for the requested mail sender. Default: mailAccount
      --ldap-starttls                 If this option is given, use StartTLS. Default: false
      --ldap-tls-cafile               File containing TLS CA certificate(s). Default:
      --ldap-tls-client-cert          File containing a TLS client certificate. Default:
      --ldap-tls-client-key           File containing a TLS client key. Default:
      --ldap-sasl-external            Use SASL/EXTERNAL instead of a simple bind. Default: false
      --ldap-scope                    LDAP search scope [base, one, sub]. Default: sub
  -v  --verbose                       Verbose mode. Repeat this for an increased log level
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

## Stats options

```shell
geoip-policyd stats --help
```

produces the following output:

```
usage: geoip-policyd stats [-h|--help] [--print-whitelist] [--http-uri
                     "<value>"] [-v|--verbose] [--version]

                     Get statistics from geoip-policyd server

Arguments:

  -h  --help             Print help information
      --print-whitelist  Print out the currently loaded whitelist (JSON-format)
      --http-uri         HTTP URI to the REST server; default(http://127.0.0.1:8080)
  -v  --verbose          Verbose mode
      --version          Current version
```
## Environment variables

The following environment variables can be used to configure the policy service. This is especially useful, if you plan
on running the service as a docker service.

### Server

Variable | Description
---|---
SERVER_ADDRESS | IPv4 or IPv6 address for the policy service; default(127.0.0.1)
SERVER_PORT | Port for the policy service; default(4646)
SERVER_HTTP_ADDRESS | HTTP address for incoming requests; default(:8080)
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
USE_LDAP | Enable LDAP support; default(false)
LDAP_SERVER_URIS | Server URI. Specify multiple times, if you need more than one server; default(ldap://127.0.0.1:389/)
LDAP_BASEDN | Base DN
LDAP_BINDDN | Bind DN 
LDAP_BINDPW_PATH | File containing the LDAP users password
LDAP_FILTER | Filter with %s placeholder; default( (&(objectClass=*)(mailAlias=%s)) )
LDAP_RESULT_ATTRIBUTE | Result attribute for the requested mail sender; default(mailAccount)
LDAP_STARTTLS | If this option is given, use StartTLS
LDAP_TLS_CAFILE | File containing TLS CA certificate(s)
LDAP_TLS_CLIENT_CERT | File containing a TLS client certificate
LDAP_TLS_CLIENT_KEY | File containing a TLS client key
LDAP_SASL_EXTERNAL | Use SASL/EXTERNAL instead of a simple bind; default(false)
LDAP_SCOPE | LDAP search scope [base, one, sub]; default(sub)
VERBOSE | Log level. One of 'none', 'info' or 'debug'

### Reload

Variable | Description
---|---
HTTP_URI | http://127.0.0.1:8080
VERBOSE | Log level. One of 'none', 'info' or 'debug'

### Stats

Variable | Description
---|---
HTTP_URI | http://127.0.0.1:8080
VERBOSE | Log level. One of 'none', 'info' or 'debug'

## LDAP

You can use LDAP to send the sender attribute and to retrieve whatever that makes your request unique. If you have
customers that use virtual aliases and that belong to exactly one account, this may help you to aggregate e-mail sender
requests.

Example:

virtual alias | real account
----|----
user1@example.com | unique@account.net
foo@bar.org | unique@account.net

Both belong to one and the same account. Without LDAP this would result in two records in Redis. With LDAP it results
into the real unique account.

It is also possible to not retrieve another unique mail account from LDAP. You can also return the entryUUID field or
some other field like uid or uniqueIdentifier (LDAP overlay unique to enforce uniqueness!).

Here is my personal example of a docker-compose.yml file that makes use of LDAP:

```yaml
version: "3.8"

services:

  geoip-policyd:
    image: ...whatever.../geoip-policyd:latest
    logging:
      driver: journald
      options:
        tag: geoip-policyd
    network_mode: host
    environment:
      TZ: "Europe/Berlin"
      VERBOSE: "debug"
      SERVER_ADDRESS: "127.0.0.1"
      SERVER_PORT: 4646
      SERVER_HTTP_ADDRESS: "127.0.0.1:8080"
      REDIS_ADDRESS: "127.0.0.1"
      REDIS_PORT: 6379
      REDIS_DATABASE_NUMBER: 0
      GEOIP_PATH: "/GeoLite2-City.mmdb"
      WHITELIST_PATH: "/whitelist.json"
      USE_LDAP: "true"
      LDAP_STARTTLS: "true"
      LDAP_SASL_EXTERNAL: "true"
      LDAP_SERVER_URIS: "ldap://****:389/, ldap://****:389/"
      LDAP_BASEDN: "ou=people,..."
      LDAP_TLS_CAFILE: "/cacert.pem"
      LDAP_TLS_CLIENT_CERT: "/cert.pem"
      LDAP_TLS_CLIENT_KEY: "/key.pem"
      LDAP_FILTER: "(&(objectClass=rnsMSDovecotAccount)(objectClass=rnsMSPostfixAccount)(rnsMSRecipientAddress=%s))"
      LDAP_RESULT_ATTRIBUTE: "uid"
    volumes:
      - /usr/share/GeoIP/GeoLite2-City.mmdb:/GeoLite2-City.mmdb:ro,Z
      - ./whitelist.json:/whitelist.json:ro,Z
      - /etc/pki/tls/certs/cacert.pem:/cacert.pem:ro,Z
      - /etc/ssl/certs/cert.pem:/cert.pem:ro,Z
      - /etc/ssl/private/key.pem:/key.pem:ro,Z
```

A result in the logs looks like this:

```
geoip-policyd_1  | 2021/09/14 06:53:28 Info: sender=<2F7032A7-D2BE-4178-87B2-A8D3AC0F32F1>; countries=[DE]; ip_addresses=[x.x.x.x]; #countries=1/1; #ip_addresses=1/1; action=DUNNO
```

Redis-result:

    127.0.0.1:6379> get geopol_2F7032A7-D2BE-4178-87B2-A8D3AC0F32F1

```json
"{\"Ips\":[\"x.x.x.x\"],\"Countries\":[\"DE\"]}"
```

This way you get some pseudo anonymization.

If you do so, you also have to modify your whitelist.json file, if you use one:

```json
{
  "data": [
    {
      "comment": "Some comment",
      "sender": "4FFDDFD3-BE1B-4639-8465-32A9A709F4CF",
      "ips": 5,
      "countries": 2
    },
    {
      "comment": "Whatever else",
      "sender": "2F7032A7-D2BE-4178-87B2-A8D3AC0F32F1",
      "ips": 1,
      "countries": 1
    },
    {
      "comment": "And another one goes here",
      "sender": "6B806FF8-8BA5-40CC-A0FE-602CF2AEEDE2",
      "countries": 1
    }
  ]
}
```

Hope you enjoy :-)