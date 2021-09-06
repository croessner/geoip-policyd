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
service and run the *geoip-policyd* container in bridged mode. Currently, the application only supports one Redis server
for reading and writing. This might change in the future. There is also no support for specifying the database number or
any auth token/ACLs (yet).

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