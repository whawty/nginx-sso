# whawty.nginx-sso

[![Go Report Card](https://goreportcard.com/badge/github.com/whawty/nginx-sso)](https://goreportcard.com/report/github.com/whawty/nginx-sso)

whawty-nginx-sso is a simple agent that can be used to implement a cookie-based SSO scheme for
the web. For this purpose the agent hosts a login form to prompt users for login credentials.
These credentials are then verified using the configured authentication backend and in case they
match a session cookie will be generated. The cookie is signed using an asymmetric signature
algorithm and can whence be verfied by other whawty-nginx-sso instances which don't need to have
access to the private signing key.
To control the access to services the whawty-nginx-sso agent offers a endpoint intended to be
used with the [ngx_http_auth_request_module](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html).
Depending on the cookie options configured the session-cookies generated can be used for all
services of a given domain. Even if those services are hosted by different machines as long as
they are published by nginx. Either directly or in the form of a reverse-proxy.

At the moment whawty-nginx-sso has support for 3 authentication backends

 * static files (htpasswd)
 * [whawty-auth](https://github.com/whawty/auth) (including support for remote-upgrades)
 * LDAP

The built-in web UI also allows users to list all currently valid sessions as well as logout
buttons that allow the user to revoke any active session. Prematurely revoked session will then
be synced to all verify-only instances to make sure those session cookies will no longer be
accepted.

For now whawty-nginx-sso only supports username and passwords but there are plans to support
multi-factor authentication as long as the authentication backend supports it.


## License

    3-clause BSD

    © 2023 whawty contributors (see AUTHORS file)
