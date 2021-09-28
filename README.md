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

The service is configured in Postfix like this:

## Postfix integration

```
smtpd_sender_restrictions =
    ...
    check_policy_service inet:127.0.0.1:4646
    ...
```

if you use the docker-compose.yml file as provided.

## Server options

```shell
geoip-policyd server --help
```

produces the following output:

```
...

Arguments:

  -h  --help                          Print help information
  -a  --server-address                IPv4 or IPv6 address for the policy service. Default: 127.0.0.1
  -p  --server-port                   Port for the policy service. Default: 4646
      --http-address                  HTTP address for incoming requests. Default: 127.0.0.1:8080
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
      --blocked-no-expire             Do not expire senders from Redis, if they were blocked in the past. Default: false
  -c  --custom-settings-path          Custom settings with different IP and country limits. Default: 
      --http-use-basic-auth           Enable basic HTTP auth. Default: false
      --http-use-ssl                  Enable HTTPS. Default: false
      --http-basic-auth-username      HTTP basic auth username. Default: 
      --http-basic-auth-password      Whitelist with different IP and country limits. Default: 
      --http-tls-cert                 HTTP TLS server certificate (full chain). Default: /localhost.pem
      --http-tls-key                  HTTP TLS server key. Default: /localhost-key.pem
      --use-ldap                      Enable LDAP support. Default: false
      --ldap-server-uri               Server URI. Specify multiple times, if you need more than one server. Default: [ldap://127.0.0.1:389/]
      --ldap-basedn                   Base DN. Default: 
      --ldap-binddn                   Bind DN. Default: 
      --ldap-bindpw                   Bind password. Default: 
      --ldap-filter                   Filter with %s placeholder. Default: (&(objectClass=*)(mailAlias=%s))
      --ldap-result-attribute         Result attribute for the requested mail sender. Default: mailAccount
      --ldap-starttls                 If this option is given, use StartTLS. Default: false
      --ldap-skip-tls-verify          Skip TLS server name verification. Default: false
      --ldap-tls-cafile               File containing TLS CA certificate(s). Default: 
      --ldap-tls-client-cert          File containing a TLS client certificate. Default: 
      --ldap-tls-client-key           File containing a TLS client key. Default: 
      --ldap-sasl-external            Use SASL/EXTERNAL instead of a simple bind. Default: false
      --ldap-scope                    LDAP search scope [base, one, sub]. Default: sub
      --run-actions                   Run actions, if a sender is over limits. Default: false
      --run-action-operator           Run the operator action. Default: false
      --operator-to                   E-Mail To-header for the operator action. Default: 
      --operator-from                 E-Mail From-header for the operator action. Default: 
      --operator-subject              E-Mail Subject-header for the operator action. Default: [geoip-policyd] An e-mail account was compromised
      --operator-message-ct           E-Mail Content-Type-header for the operator action. Default: text/plain
      --operator-message-path         Full path to the e-mail message file for the operator action. Default: 
      --mail-server                   E-mail server address for notifications. Default: 
      --mail-helo                     E-mail server HELO/EHLO hostname. Default: localhost
      --mail-port                     E-mail server port number. Default: 587
      --mail-username                 E-mail server username. Default: 
      --mail-password                 E-mail server password. Default: 
      --mail-ssl                      Use TLS on connect for the e-mail server. Default: false
  -v  --verbose                       Verbose mode. Repeat this for an increased log level
      --version                       Current version
```

## GET request /reload

Request: reload     
Response: No results

Example:

```shell
# Plain http without basic auth
curl "http://localhost:8080/reload"

# Plain with basic auth
curl "http://localhost:8080/reload" -u testuser:testsecret

# Secured with basic auth
curl -k "https://localhost:8443/remove" -u testuser:testsecret
```

## GET request /custom-settings

Request: get current custom settings in JSON format     
Response: JSON output of the currently loaded custom settings

Example:

```shell
# Plain http without basic auth
curl "http://localhost:8080/custom-settings" | jq

# Plain with basic auth
curl "http://localhost:8080/custom-settings" -u testuser:testsecret | jq

# Secured with basic auth
curl -k "https://localhost:8443/custom-settings" -u testuser:testsecret | jq
```

Example result from default custom.json:

```json
[
  {
    "comment": "Allow only two countries and a maximum of 5 IP addresses",
    "sender": "christian@roessner.email",
    "ips": 5,
    "countries": 2
  },
  {
    "comment": "Allow at least 4 countries and go with the default IP address limit",
    "sender": "test1@example.com",
    "ips": 0,
    "countries": 4
  },
  {
    "comment": "Go with the default country limit, but allow up to 30 IP addresses",
    "sender": "test2@example.com",
    "ips": 30,
    "countries": 0
  }
]
```

## POST request /remove

Request: Submit an email account that should be unlocked        
Response: No results

Example:

```shell
# Plain http without basic auth
curl -d '{"key":"sender","value":"user@example.com"' -H "Content-Type: application/json" -X POST "http://localhost:8080/remove"

# Plain with basic auth
curl -d '{"key":"sender","value":"user@example.com"' -H "Content-Type: application/json" -X POST "http://localhost:8080/remove" -u testuser:testsecret

# Secured with basic auth
curl -k -d '{"key":"sender","value":"user@example.com"' -H "Content-Type: application/json" -X POST "https://localhost:8443/remove" -u testuser:testsecret
```

## PUT request /update

Request: Set custom settings. This will overwrite a custom settings file or initiates settings, if there have
not been any settings before (no config file given).       
Response: No results

---
***Note***

If you use a custom settings file and send new data with a PUT request, the settings are updated in memory. But if you
do a GET request afterwards and reloading data, the settings from the file will be loaded again!

---

Example:

```shell
# Plain http without basic auth
curl -d '{"data":[{ "sender":"christian@roessner.email","ips":3,"countries":1},{"sender":"test1@example.com","countries":1},{"sender":"test2@example.com","ips":20}]}' -H "Content-Type: application/json" -X PUT "http://localhost:8080/remove"

# Plain with basic auth
curl -d '{"data":[{ "sender":"christian@roessner.email","ips":3,"countries":1},{"sender":"test1@example.com","countries":1},{"sender":"test2@example.com","ips":20}]}' -H "Content-Type: application/json" -X PUT "http://localhost:8080/remove" -u testuser:testsecret

# Secured with basic auth
curl -k -d '{"data":[{ "sender":"christian@roessner.email","ips":3,"countries":1},{"sender":"test1@example.com","countries":1},{"sender":"test2@example.com","ips":20}]}' -H "Content-Type: application/json" -X PUT "https://localhost:8443/remove" -u testuser:testsecret
```

---
***Note***

It is currently not possible to update a single record. This might be implemented somewhere in the future by a PATCH request.

---

## Environment variables

The following environment variables can be used to configure the policy service. This is especially useful, if you plan
on running the service as a docker service.

### Server

Variable | Description
---|---
SERVER_ADDRESS | IPv4 or IPv6 address for the policy service; default(127.0.0.1)
SERVER_PORT | Port for the policy service; default(4646)
HTTP_ADDRESS | HTTP address for incoming requests; default(127.0.0.1:8080)
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
BLOCKED_NO_EXPIRE | Do not expire senders from Redis, if they were blocked in the past
CUSTOM_SETTINGS_PATH | Custom settings with different IP and country limits
HTTP_USE_BASIC_AUTH | Enable basic HTTP auth; default(false)
HTTP_USE_SSL | Enable HTTPS; default(false)
HTTP_BASIC_AUTH_USERNAME | HTTP basic auth username
HTTP_BASIC_AUTH_PASSWORD | HTTP basic auth password
HTTP_TLS_CERT | HTTP TLS server certificate (full chain); default(/localhost.pem)
HTTP_TLS_KEY | HTTP TLS server key; default(/localhost-key.pem)
USE_LDAP | Enable LDAP support; default(false)
LDAP_SERVER_URIS | Server URI. Specify multiple times, if you need more than one server; default(ldap://127.0.0.1:389/)
LDAP_BASEDN | Base DN
LDAP_BINDPW | Bind PW 
LDAP_FILTER | Filter with %s placeholder; default( (&(objectClass=*)(mailAlias=%s)) )
LDAP_RESULT_ATTRIBUTE | Result attribute for the requested mail sender; default(mailAccount)
LDAP_STARTTLS | If this option is given, use StartTLS
LDAP_TLS_SKIP_VERIFY | Skip TLS server name verification
LDAP_TLS_CAFILE | File containing TLS CA certificate(s)
LDAP_TLS_CLIENT_CERT | File containing a TLS client certificate
LDAP_TLS_CLIENT_KEY | File containing a TLS client key
LDAP_SASL_EXTERNAL | Use SASL/EXTERNAL instead of a simple bind; default(false)
LDAP_SCOPE | LDAP search scope [base, one, sub]; default(sub)
RUN_ACTIONS | Run actions, if a sender is over limits; default(false)
RUN_ACTION_OPERATOR | Run the operator action; default(false)
OPERATOR_TO | E-Mail To-header for the operator action
OPERATOR_FROM | E-Mail From-header for the operator action
OPERATOR_SUBJECT | E-Mail Subject-header for the operator action; default([geoip-policyd] An e-mail account was compromised)
OPERATOR_MESSAGE_CT | E-Mail Content-Type-header for the operator action; default(text/plain)
OPERATOR_MESSAGE_PATH | Full path to the e-mail message file for the operator action
MAIL_SERVER | E-mail server address for notifications
MAIL_HELO | E-mail server HELO/EHLO hostname; default(localhost)
MAIL_PORT | E-mail server port number; default(587)
MAIL_USERNAME | E-mail server username
MAIL_PASSWORD | E-mail server password
MAIL_SSL | Use TLS on connect for the e-mail server; default(false)
VERBOSE | Log level. One of 'none', 'info' or 'debug'

## Actions

You can activate actions that will be taken, if a sender was declared compromised. At the moment you can send a
notification to an e-mail operator. To do this, you must activate actions in general as well as the operator action.
You need also to define all the required operator parameters as To, From, Subject, CT and of course an e-mail server (
including all required settings) to get things done.

If you need to authenticate to the e-mail server, please put the password in a file with appropriate permissions.

Example:
```shell
geoip-policyd ...other-options... \
  --run-actions \
  --run-action-operator \
  --operator-to "<operator@example.com>" \
  --operator-from "<no-reply@submission.example.com>" \
  --operator-message-ct "text/plain" \
  --operator-message-path ./mailtemplate.txt \
  --mail-server submission.example.com \
  --mail-port 587 \
  --mail-username "some_username" \
  --mail-password some-secret
```

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
      HTTP_ADDRESS: "127.0.0.1:8080"
      REDIS_ADDRESS: "127.0.0.1"
      REDIS_PORT: 6379
      REDIS_DATABASE_NUMBER: 0
      GEOIP_PATH: "/GeoLite2-City.mmdb"
      CUSTOM_SETTINGS_PATH: "/custom.json"
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
      - ./custom.json:/custom.json:ro,Z
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