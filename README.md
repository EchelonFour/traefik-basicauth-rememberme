# traefik-basicauth-rememberme

Acts as a server to handle authentication with traefik's forward auth middleware, where the login is saved in a cookie

## How it works

This is a very simple web server designed to respond to the [ForwardAuth](https://doc.traefik.io/traefik/v2.5/middlewares/http/forwardauth/) Middleware of Traefik. It will let a user in for 2 different reasons:

- Basic Authentication valid
- Cookie Authentication valid
  When the Basic authentication passes, it sets a cookie so that later requests pass the Cookie authentication.

## Install

First, you will need to run traefik-basicauth-rememberme as a docker container side by side with traefik. Here is a minimal config for docker-compose:

```yml
version: "3.3"
services:
  basicauth-rememberme:
    image: ghcr.io/echelonfour/traefik-basicauth-rememberme:latest
    environment:
      - app_htpasswd_contents: "user:$apr1$1ur4bznk$2F7FRzHneSe7hzM7yAR76/" #htpasswd fiile format (you can comma seperate instead of newline too)
      - app_secret: "I+2cI023PGtRvdlDWNs4TR6HTRb9f1Oj6dNV/kSWJ20=" #DO NOT USE THIS STRING. random 32 bytes as base64. Can be generated with `openssl rand -base64 32`
```

You can then set up the middleware for traefik like so (using the file provider notation):

```yml
http:
  middlewares:
    remember:
      chain:
        middlewares:
          - rememberAuth
          - headersAuth
    rememberAuth:
      forwardAuth:
        address: http://basicauth-rememberme/auth
        authResponseHeaders:
          - "X-User"
    headersAuth:
      headers:
        customrequestheaders:
          authorization: ""
```

You can then enable the authentication on a route using the following label:
`traefik.http.routers.route.middlewares` = `remember@file`
The reason we use the chain is to remove the `authorization` header on forwarded requests, as certain servers might incorrectly try to act on it.
You will need to make sure that traefik can communicate to the traefik-basicauth-rememberme container with port 80. Usually you would attach both containers to the same docker network.

## Config

The app supports configuration with either environment variables (must be appended with `app_`, or with toml/json files. The files are read from the `{working directory}/config/default.{toml,json}` or `{working directory}/config/{RUN_MODE}.{toml,json}` where `RUN_MODE` is the environment variable.
|Key|Default|Description|
|--|--|--|
| secret | None | Required random secret to use for encrypting the cookie. Must be at least 32 bytes long and base64 format. Can be generated with `openssl rand -base64 32`. |
| htpasswd_path | "./.htpasswd" | Location of htpasswd we might attempt to read. |
| htpasswd_contents | None | Contents of the htpasswd file. Can be comma seperated instead of newline. Overrides reading of file at `htpasswd_path` config location. |
| realm | "Please sign in" | Basic Auth Realm in challenge. |
| cookie_name | "\_auth_remember_me" | Name of the cookie that the server saves the session as. |
| cookie_domain | None | If set, will use this domain as the cookie's domain (but only if the incoming host would allow it). |
| cookie_lifetime | permanent | Lifetime of cookie. Can be either "permanent" or "session" or a duration parsable by [humantime](https://docs.rs/humantime/2.1.0/humantime/). |
| user_header | "x-user" | Header to set saying the name of user that authenticated. Can be used in traefik forwardauth settings. |
| listen | "0.0.0.0:80" | Where the http server listens. |
| no_save_enabled | True | Allows you to append "-nosave" to your user when logging in to disable the cookie save feature temporarily. Useful for tools that can't handle the redirect response, but could collide with your usernames. |

## License

[MIT](http://opensource.org/licenses/MIT)
