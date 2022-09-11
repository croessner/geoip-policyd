# geoip-policyd

## About

Postfix-Submission policy server that checks sender IPs and blocks senders, if they come from too many countries or if
they come from too many IP addresses.

## Features

* GeoIP policy service for Postfix
* Custom settings to define different limits for IPs and countries per sender
* LDAP support (optional)
* REST interface to interact with the service on the fly
* Actions

# Table of contents

1. [Install](#install)
    * [Postfix integration](#postfix-integration)
    * [Custom settings](#custom-settings)
    * [Preparing a docker image](#preparing-a-docker-image)
    * [Server options](#server-options)
2. [Environment variables](#environment-variables)
    * [Server](#server)
3. [REST interface](#rest-interface)
    * [GET request /reload](#get-request-reload)
    * [GET request /custom-settings](#get-request-custom-settings)
    * [POST request /remove](#post-request-remove)
    * [PUT request /update](#put-request-update)
    * [PATCH request /modify](#patch-request-modify)
    * [DELETE request /remove](#delete-request-remove)
4. [Actions](#actions)
    * [Operator action](#operator-action)
5. [LDAP](#ldap)
    * [docker-compose.yml](#docker-composeyml)
    * [custom.json](#customjson)

# Install

## Postfix integration

The service is configured in Postfix like this...

```
smtpd_sender_restrictions =
    ...
    check_policy_service inet:127.0.0.1:4646
    ...
```

... if you use the docker-compose.yml file as provided.

Back to [table of contents](#table-of-contents)

## Custom settings

You can specify custom settings, which must be written in valid JSON. The format is:

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

Back to [table of contents](#table-of-contents)

## Preparing a docker image

The simplest way to use the program is by using a docker image. You can build your own, as the default repository is not
public for other people.

```shell
cd /path/to/Dockerfile
docker build -t geoip-policyd:latest .
```

You need to change the docker-compose.yml file as well. If you prefer, you can add a Redis service and run the *
geoip-policyd* container in bridged mode.

For a complete example see [here](docker-compose.yml)

Back to [table of contents](#table-of-contents)

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
      --http-address                  HTTP address for incoming requests. Default: 127.0.0.1
      --http-port                     HTTP port for incoming requests. Default 8080
      --sasl-username                 Use 'sasl_username' instead of the 'sender' attribute. Default: false
  -A  --redis-address                 IPv4 or IPv6 address for the Redis service. Default: 127.0.0.1
  -P  --redis-port                    Port for the Redis service. Default: 6379
      --redis-database-number         Redis database number. Default: 0
      --redis-username                Redis username. Default: 
      --redis-password                Redis password. Default: 
      --redis-replica-address         IPv4 or IPv6 address for a Redis service (replica). Default: 127.0.0.1
      --redis-replica-port            Port for a Redis service (replica). Default: 6379
      --redis-replica-database-number Redis database number (replica). Default: 0
      --redis-replica-username        Redis username (replica). Default: 
      --redis-replica-password        Redis password (replica). Default: 
      --redis-sentinels               List of space seperated sentinel servers. Default:
      --redis-sentinel-master-name    Sentinel master name. Default:
      --redis-prefix                  Redis prefix. Default: geopol_
      --redis-ttl                     Redis TTL in seconds. Default: 3600
  -g  --geoip-path                    Full path to the GeoIP database file. Default: /usr/share/GeoIP/GeoLite2-City.mmdb
      --max-countries                 Maximum number of countries before rejecting e-mails. Default: 3
      --max-ips                       Maximum number of IP addresses before rejecting e-mails. Default: 10
      --block-permanent               Do not expire senders from Redis, if they were blocked in the past. Default: false
  -c  --custom-settings-path          Custom settings with different IP and country limits. Default: 
      --http-use-basic-auth           Enable basic HTTP auth. Default: false
      --http-use-ssl                  Enable HTTPS. Default: false
      --http-basic-auth-username      HTTP basic auth username. Default: 
      --http-basic-auth-password      HTTP basic auth password. Default: 
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
      --ldap-pool-size                LDAP pre-forked pool size. Default: 10
      --run-actions                   Run actions, if a sender is over limits. Default: false
      --run-action-operator           Run the operator action. Default: false
      --operator-to                   E-Mail To-header for the operator action. Default: 
      --operator-from                 E-Mail From-header for the operator action. Default: 
      --operator-subject              E-Mail Subject-header for the operator action. Default: [geoip-policyd] An e-mail account was compromised
      --operator-message-ct           E-Mail Content-Type-header for the operator action. Default: text/plain
      --operator-message-path         Full path to the e-mail message file for the operator action. Default: 
      --mail-server-address           E-mail server address for notifications. Default: 
      --mail-server-port              E-mail server port number. Default: 
      --mail-helo                     E-mail server HELO/EHLO hostname. Default: localhost
      --mail-port                     E-mail server port number. Default: 587
      --mail-username                 E-mail server username. Default: 
      --mail-password                 E-mail server password. Default: 
      --mail-ssl-on-connect           Use TLS on connect for the e-mail server. Default: false
  -v  --verbose                       Verbose mode. Repeat this for an increased log level
      --version                       Current version
```

Back to [table of contents](#table-of-contents)

# Environment variables

The following environment variables can be used to configure the policy service. This is especially useful, if you plan
on running the service as a docker service.

## Server

| Variable                                   | Description                                                                                               |
|--------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| GEOIPPOLICYD_SERVER_ADDRESS                | IPv4 or IPv6 address for the policy service; default(127.0.0.1)                                           |
| GEOIPPOLICYD_SERVER_PORT                   | Port for the policy service; default(4646)                                                                |
| GEOIPPOLICYD_HTTP_ADDRESS                  | HTTP address for incoming requests; default(127.0.0.1:8080)                                               |
 | GEOIPPOLICYD_HTTP_PORT                     | HTTP port for incoming requests; default(8080)                                                            |
| GEOIPPOLICYD_USE_SASL_USERNAME             | Use 'sasl_username' instead of the 'sender' attribute; default(false)                                     |
| GEOIPPOLICYD_REDIS_ADDRESS                 | IPv4 or IPv6 address for the Redis service; default(127.0.0.1)                                            |
| GEOIPPOLICYD_REDIS_PORT                    | Port for the Redis service; default(6379)                                                                 |
| GEOIPPOLICYD_REDIS_DATABASE_NUMBER         | Redis database number                                                                                     |
| GEOIPPOLICYD_REDIS_USERNAME                | Redis username                                                                                            |
| GEOIPPOLICYD_REDIS_REPLICA_ADDRESS         | IPv4 or IPv6 address for a Redis service (replica)                                                        |
| GEOIPPOLICYD_REDIS_REPLICA_PORT            | Port for a Redis service (replica)                                                                        |
| GEOIPPOLICYD_REDIS_REPLICA_DATABASE_NUMBER | Redis database number (replica)                                                                           |
| GEOIPPOLICYD_REDIS_REPLICA_USERNAME        | Redis username (replica)                                                                                  |
| GEOIPPOLICYD_REDIS_REPLICA_PASSWORD        | Redis password (replica)                                                                                  |
| GEOIPPOLICYD_REDIS_SENTINELS               | List of space seperated sentinel servers                                                                  |
| GEOIPPOLICYD_REDIS_SENTINEL_MASTER_NAME    | Sentinel master name                                                                                      |
| GEOIPPOLICYD_REDIS_PREFIX                  | Redis prefix; default(geopol_)                                                                            |
| GEOIPPOLICYD_REDIS_TTL                     | Redis TTL; default(3600)                                                                                  |
| GEOIPPOLICYD_GEOIP_PATH                    | Full path to the GeoIP database file; default(/usr/share/GeoIP/GeoLite2-City.mmdb)                        |
| GEOIPPOLICYD_MAX_COUNTRIES                 | Maximum number of countries before rejecting e-mails; default(3)                                          |
| GEOIPPOLICYD_MAX_IPS                       | Maximum number of IP addresses before rejecting e-mails; default(10)                                      |
| GEOIPPOLICYD_BLOCK_PERMANENT               | Do not expire senders from Redis, if they were blocked in the past                                        |
| GEOIPPOLICYD_CUSTOM_SETTINGS_PATH          | Custom settings with different IP and country limits                                                      |
| GEOIPPOLICYD_HTTP_USE_BASIC_AUTH           | Enable basic HTTP auth; default(false)                                                                    |
| GEOIPPOLICYD_HTTP_USE_SSL                  | Enable HTTPS; default(false)                                                                              |
| GEOIPPOLICYD_HTTP_BASIC_AUTH_USERNAME      | HTTP basic auth username                                                                                  |
| GEOIPPOLICYD_HTTP_BASIC_AUTH_PASSWORD      | HTTP basic auth password                                                                                  |
| GEOIPPOLICYD_HTTP_TLS_CERT                 | HTTP TLS server certificate (full chain); default(/localhost.pem)                                         |
| GEOIPPOLICYD_HTTP_TLS_KEY                  | HTTP TLS server key; default(/localhost-key.pem)                                                          |
| GEOIPPOLICYD_USE_LDAP                      | Enable LDAP support; default(false)                                                                       |
| GEOIPPOLICYD_LDAP_SERVER_URIS              | Server URI. Specify multiple times, if you need more than one server; default(ldap://127.0.0.1:389/)      |
| GEOIPPOLICYD_LDAP_BASEDN                   | Base DN                                                                                                   |
| GEOIPPOLICYD_LDAP_BINDPW                   | Bind PW                                                                                                   |
| GEOIPPOLICYD_LDAP_FILTER                   | Filter with %s placeholder; default( (&(objectClass=*)(mailAlias=%s)) )                                   |
| GEOIPPOLICYD_LDAP_RESULT_ATTRIBUTE         | Result attribute for the requested mail sender; default(mailAccount)                                      |
| GEOIPPOLICYD_LDAP_STARTTLS                 | If this option is given, use StartTLS                                                                     |
| GEOIPPOLICYD_LDAP_TLS_SKIP_VERIFY          | Skip TLS server name verification                                                                         |
| GEOIPPOLICYD_LDAP_TLS_CAFILE               | File containing TLS CA certificate(s)                                                                     |
| GEOIPPOLICYD_LDAP_TLS_CLIENT_CERT          | File containing a TLS client certificate                                                                  |
| GEOIPPOLICYD_LDAP_TLS_CLIENT_KEY           | File containing a TLS client key                                                                          |
| GEOIPPOLICYD_LDAP_SASL_EXTERNAL            | Use SASL/EXTERNAL instead of a simple bind; default(false)                                                |
| GEOIPPOLICYD_LDAP_SCOPE                    | LDAP search scope [base, one, sub]; default(sub)                                                          |
| GEOIPPOLICYD_LDAP_POOL_SIZE                | LDAP pre-forked pool size; default(10)                                                                    |
| GEOIPPOLICYD_RUN_ACTIONS                   | Run actions, if a sender is over limits; default(false)                                                   |
| GEOIPPOLICYD_RUN_ACTION_OPERATOR           | Run the operator action; default(false)                                                                   |
| GEOIPPOLICYD_OPERATOR_TO                   | E-Mail To-header for the operator action                                                                  |
| GEOIPPOLICYD_OPERATOR_FROM                 | E-Mail From-header for the operator action                                                                |
| GEOIPPOLICYD_OPERATOR_SUBJECT              | E-Mail Subject-header for the operator action; default([geoip-policyd] An e-mail account was compromised) |
| GEOIPPOLICYD_OPERATOR_MESSAGE_CT           | E-Mail Content-Type-header for the operator action; default(text/plain)                                   |
| GEOIPPOLICYD_OPERATOR_MESSAGE_PATH         | Full path to the e-mail message file for the operator action                                              |
| GEOIPPOLICYD_MAIL_SERVER_ADDRESS           | E-mail server address for notifications                                                                   |
| GEOIPPOLICYD_MAIL_SERVER_PORT              | E-mail server port number                                                                                 |
| GEOIPPOLICYD_MAIL_HELO                     | E-mail server HELO/EHLO hostname; default(localhost)                                                      |
| GEOIPPOLICYD_MAIL_PORT                     | E-mail server port number; default(587)                                                                   |
| GEOIPPOLICYD_MAIL_USERNAME                 | E-mail server username                                                                                    |
| GEOIPPOLICYD_MAIL_PASSWORD                 | E-mail server password                                                                                    |
| GEOIPPOLICYD_MAIL_SSL_ON_CONNECT           | Use TLS on connect for the e-mail server; default(false)                                                  |
| GEOIPPOLICYD_VERBOSE_LEVEL                 | Log level. One of 'none', 'info' or 'debug'                                                               |

Back to [table of contents](#table-of-contents)

# REST interface

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
curl -k "https://localhost:8443/reload" -u testuser:testsecret
```

Back to [table of contents](#table-of-contents)

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

Example result from default [custom.json](custom.json):

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

Back to [table of contents](#table-of-contents)

## POST request /remove

Request: Submit an email account that should be unlocked        
Response: No results

Example:

```shell
# Plain http without basic auth
curl -d '{"key":"sender","value":"user@example.com"}' -H "Content-Type: application/json" -X POST "http://localhost:8080/remove"

# Plain with basic auth
curl -d '{"key":"sender","value":"user@example.com"}' -H "Content-Type: application/json" -X POST "http://localhost:8080/remove" -u testuser:testsecret

# Secured with basic auth
curl -k -d '{"key":"sender","value":"user@example.com}"' -H "Content-Type: application/json" -X POST "https://localhost:8443/remove" -u testuser:testsecret
```

Back to [table of contents](#table-of-contents)

## PUT request /update

Request: Set custom settings. This will overwrite a custom settings file or initiates settings, if there have not been
any settings before (no config file given).       
Response: No results

---
***Note***

If you use a custom settings file and send new data with a PUT request, the settings are updated in memory. But if you
do a GET request afterwards and reloading data, the settings from the file will be loaded again!

---

Example:

```shell
# Plain http without basic auth
curl -d '{"data":[{ "sender":"christian@roessner.email","ips":3,"countries":1},{"sender":"test1@example.com","countries":1},{"sender":"test2@example.com","ips":20}]}' -H "Content-Type: application/json" -X PUT "http://localhost:8080/update"

# Plain with basic auth
curl -d '{"data":[{ "sender":"christian@roessner.email","ips":3,"countries":1},{"sender":"test1@example.com","countries":1},{"sender":"test2@example.com","ips":20}]}' -H "Content-Type: application/json" -X PUT "http://localhost:8080/update" -u testuser:testsecret

# Secured with basic auth
curl -k -d '{"data":[{ "sender":"christian@roessner.email","ips":3,"countries":1},{"sender":"test1@example.com","countries":1},{"sender":"test2@example.com","ips":20}]}' -H "Content-Type: application/json" -X PUT "https://localhost:8443/update" -u testuser:testsecret
```

Back to [table of contents](#table-of-contents)

## PATCH request /modify

Request: Send changed settings for a given sender. If the sender does not exist, add a new record to the custom
settings.       
Response: No results

Example:

````shell
# Plain http without basic auth
curl -d '{"key":"sender","value":{"comment":"Test","sender":"christian@roessner.email","ips":100,"countries":100}}' -H "Content-Type: application/json" -X PATCH "http://localhost:8080/modify"

# Plain with basic auth
curl -d '{"key":"sender","value":{"comment":"Test","sender":"christian@roessner.email","ips":100,"countries":100}}' -H "Content-Type: application/json" -X PATCH "http://localhost:8080/modify" -u testuser:testsecret

# Secured with basic auth
curl -k -d '{"key":"sender","value":{"comment":"Test","sender":"christian@roessner.email","ips":100,"countries":100}}"' -H "Content-Type: application/json" -X PATCH "https://localhost:8443/modify" -u testuser:testsecret
````

Back to [table of contents](#table-of-contents)

## DELETE request /remove

Request: Remove an entry from the custom settings by using the sender as the key.        
Response: No results

Example:

````shell
# Plain http without basic auth
curl -d '{"key":"sender","value":{"comment":"Test","sender":"christian@roessner.email","ips":100,"countries":100}}' -H "Content-Type: application/json" -X DELETE "http://localhost:8080/remove"

# Plain with basic auth
curl -d '{"key":"sender","value":{"comment":"Test","sender":"christian@roessner.email","ips":100,"countries":100}}' -H "Content-Type: application/json" -X DELETE "http://localhost:8080/remove" -u testuser:testsecret

# Secured with basic auth
curl -k -d '{"key":"sender","value":{"comment":"Test","sender":"christian@roessner.email","ips":100,"countries":100}}"' -H "Content-Type: application/json" -X DELETE "https://localhost:8443/remove" -u testuser:testsecret
````

Back to [table of contents](#table-of-contents)

# Actions

## Operator action

You can activate actions that will be taken, if a sender was declared compromised. At the moment you can send a
notification to an e-mail operator. To do this, you must activate actions in general as well as the operator action. You
need also to define all the required operator parameters as To, From, Subject, CT and of course an e-mail server (
including all required settings) to get things done.

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

Back to [table of contents](#table-of-contents)

# LDAP

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

### docker-compose.yml

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

If you do so, you also have to modify your custom.json file, if you use one:

### custom.json

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

Back to [table of contents](#table-of-contents)

Hope you enjoy :-)