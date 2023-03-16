# Introduction

This repo shows a very simple example of the OAuth 2.0 Authorization Code Grant flow in the 
context of [OpenID Connect](https://openid.net/connect/) using [Keycloak](https://www.keycloak.org)
as the Authorization Server. By looking at the trace level logging you can understand what's 
happening and see the various pieces in action. 

There's a commented selection of log messages presenting walkthroughs of the steps in the login
and logout flows.

# Setting up Keycloak

Setup steps are only needed the first time, or after you delete the `loginflow_pgdata` volume.

Docker is used to run Keycloak and a Postgres server.

To start postgres and keycloak

`docker-compose up`

Wait till you see `Running the server in development mode. DO NOT use this configuration in production.`

docker-compose starts Keycloak listening on http://localhost:8090. Visit that URL and go to the 
Administration Console. Login with user and password set in docker-compose file `admin` : `CatParlor`

Create a Realm called `MyAppRealm` by clicking on the `master` dropdown in the top left and choosing
`Create Realm`. Enter the `Realm name` and click `Create`.

From the `Clients` option in the left nav create a client with Client ID `login` in the `MyAppRealm`. 
Leave the `Capability config` settings with the default values. On the `Login settings` panel set 
the `Valid redirect URIs` to `http://localhost:8100/*`. This is the pattern for URIs we want to 
allow Keycloak to redirect to after login.

On the `Client details` screen that's displayed after the client is created choose the `Roles` tab.
Create a Role called `user`.

Choose `Users` from the left nav and `Create new user` with Username `alfred@bob.com`. 

On the `User details` screen shown after the user has been created choose the `Credentials` tab.
Set the initial password to `DownSideTrain`, or whatever you want, you'll need it to login. Uncheck
the `Temporary` toggle so that we don't have to change the password immediately after first login.

Choose the `Role mapping` tab and click the `Assign role` tab.  Change the `Filter by realm roles` 
dropdown to `Filter by clients`. Choose the `user` role and click assign. Now we have a user with a
password and a role of `user`. Next we need to configure things so that this information is available
to our spring-boot client in the wanted format.

Choose `Client scopes` from the left nav. Choose the `roles` scope. This is where we add user roles
to the access toke. Select the `Mappers` tab.

Choose the `client roles` mapper. Change the `Token Clain Name` to `roles`. Check the 
`Add to userinfo` toggle. Click save. This makes the roles assigned to a user available under the 
`roles` claim in the userInfo object. See 
[KeycloakGrantedAuthoritiesMapper](src/main/java/com/zanthan/client/security/KeycloakGrantedAuthoritiesMapper.java)
for how the roles are extracted.

# Executing the ClientApplication

Using java 19. There's a `.java-version` file if you use [jenv](https://www.jenv.be/). 

From a terminal window run `./mvnw spring-boot:run`

Once you see `Application availability state ReadinessState changed to ACCEPTING_TRAFFIC` in the 
output you can navigate to `http://localhost:8100`. Click on the `hello` link to try to access the 
protected hello resource.

You'll be redirected to the Keycloak server on port 8090 to enter your user `alfred@bob.com` and 
password. After successful login you'll be redirected back to `http://localhost:8100/hellp?continue`.

This shows a `logout` button that posts to `/logout` invoking the KeycloakLogoutHandler and 
logging you out of Keycloak. Clicking the `hello` link again will again redirect to Keycloak for auth.

# A Description of the Login Flow with log messages

The overall flow is described in [OpenID Connect explained](https://connect2id.com/learn/openid-connect)
in the section [6. Example OpenID authentication](https://connect2id.com/learn/openid-connect#example-auth-code-flow).

The extracts from the logs below explain what happens during the login and logout flow. For more
information on what each class does see the javadoc comments and code for the class.

Logging level set to `trace` in [application.yaml](src/main/resources/application.yaml).

## Server Startup

```
16:16:43.998 o.s.web.client.RestTemplate              : HTTP GET http://localhost:8090/realms/MyAppRealm/.well-known/openid-configuration
```

During server startup / initialization the Keycloak server's configuration is read from the 
`.well-known/openid-configuration` endpoint. This provides the information needed later in
the process to find the authorization and token endpoints. The `.well-known` endpoint is
defined by the OpenID Connect standards.

## Login Flow

Skipping over the prefetch that Chrome does and starting with the first request for the `/hello`
endpoint.

```
16:16:51.566 o.a.coyote.http11.Http11InputBuffer      : Received [GET /hello HTTP/1.1
```

The `org.springframework.security.web.FilterChainProxy` invokes the configured `SecurityFilterChain`
instances in order.

```
16:16:51.570 o.s.security.web.FilterChainProxy        : Securing GET /hello
16:16:51.570 o.s.security.web.FilterChainProxy        : Invoking DisableEncodeUrlFilter (1/16)
```

`DisableEncodeUrlFilter` wraps the response to prevent inclusion of session id in URLs. We don't 
want session ids in logs etc. and we're going to use cookies for sessions.

```
16:16:51.570 o.s.security.web.FilterChainProxy        : Invoking WebAsyncManagerIntegrationFilter (2/16)
```

`WebAsyncManagerIntegrationFilter` sets things up so that the `SecurityContext` can be made 
available to async processing if needed.

```
16:16:51.570 o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderFilter (3/16)
```

`SecurityContextHolderFilter` provides `SecurityContextRepository` with a supplier than will provide
a `SecurityContext` if needed. For example this may provide a supplier that retrieves the 
`SecurityContext` from the `HttpSession`.

```
16:16:51.570 To.s.security.web.FilterChainProxy        : Invoking HeaderWriterFilter (4/16)
```

`HeaderWriterFilter`. Standard headers such as 
`Cache-Control: no-cache, no-store, max-age=0, must-revalidate` are added by this filter using
`HeaderWriter` instances provided by `HeaderConfigurer`.

```
16:16:51.570 o.s.security.web.FilterChainProxy        : Invoking CsrfFilter (5/16)
```

`CsrfFilter` applies CSRF protection to requests that should have it. It checks that the token
in the request matches that from the `CsrfTokenRepository`.

```
16:16:51.570 o.s.security.web.FilterChainProxy        : Invoking LogoutFilter (6/16)
```

`LogoutFilter` sees if the request matches the pattern for a logout, by default a POST to `/logout`, 
and if it does calls the registered `LogoutHander` instances. One of these is the 
`KeycloakLogoutHandler` that logs the user out from Keycloak.

```
16:16:51.570 o.s.security.web.FilterChainProxy        : Invoking OAuth2AuthorizationRequestRedirectFilter (7/16)
```

`OAuth2AuthorizationRequestRedirectFilter` sees if the request matches an authorization request. By
default this is `/oauth2/authorization/{registrationId}` so `/oauth2/authorization/keycloak` in this
case. If there's a match then a redirect is returned to send the user's browser to the authorization
endpoint. The filter also handles `ClientAuthorizationRequiredException` thrown by filters lower in
the chain and also redirects in that case.

```
16:16:51.571 o.s.security.web.FilterChainProxy        : Invoking OAuth2LoginAuthenticationFilter (8/16)
16:16:51.571 .s.o.c.w.OAuth2LoginAuthenticationFilter : Did not match request to Ant [pattern='/login/oauth2/code/*']
```

`OAuth2LoginAuthenticationFilter` handles the response from the Open ID provider that comes back 
when the user has logged in on the authorization endpoint they've been redirected to by the
`OAuth2AuthorizationRequestRedirectFilter`. If authentication is successful this is where the 
authentication is saved in the `OAuth2AuthorizedClientRepository`. Here the request does not match
the pattern.

```
16:16:51.571 o.s.security.web.FilterChainProxy        : Invoking DefaultLoginPageGeneratingFilter (9/16)
```

`DefaultLoginPageGeneratingFilter` generates a default login page for the `/login` URI. If the app 
is configured for OAuth 2 then it shows a link to the OAuth 2 authorization provider. If a login
page is configured this filter is not added to the filter chain.

```
16:16:51.571 o.s.security.web.FilterChainProxy        : Invoking DefaultLogoutPageGeneratingFilter (10/16)
```

`DefaultLogoutPageGeneratingFilter` generates an HTML page to handle a get request to the `/logout`
endpoint. For security logout must be handled by a POST with a csrf token so the generated page is
a form that posts to `/logout`.

```
16:16:51.571 o.s.security.web.FilterChainProxy        : Invoking BearerTokenAuthenticationFilter (11/16)
```

`BearerTokenAuthenticationFilter` looks for an OAuth 2.0 bearer token.

```
16:16:51.572 o.s.security.web.FilterChainProxy        : Invoking RequestCacheAwareFilter (12/16)
```

`RequestCacheAwareFilter` uses a `RequestCache` to handle restarting the request that was paused
during redirection through the authentication flow.

```
16:16:51.572 o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderAwareRequestFilter (13/16)
```

`SecurityContextHolderAwareRequestFilter` wraps the ServletRequest to provide implementations of the
Servlet API security methods like `isUserInRole` or `login`.

```
16:16:51.572 o.s.security.web.FilterChainProxy        : Invoking AnonymousAuthenticationFilter (14/16)
```

`AnonymousAuthenticationFilter` adds an `Authentication` object representing an anonymous user to 
the `SecurityContextHolder` if the code gets to this point and no earlier filter has provided a
context. After authentication the `SecurityContextHolderFilter` will have provided one earlier. 

```
16:16:51.572 o.s.security.web.FilterChainProxy        : Invoking ExceptionTranslationFilter (15/16)
```

`ExceptionTranslationFilter` handles `AccessDeniedException` and `AuthenticationException` thrown
from later in the filter chain. This is where an `AccessDeniedException` for an anonymous user is
used to trigger the authentication process.

```
16:16:51.572 o.s.security.web.FilterChainProxy        : Invoking AuthorizationFilter (16/16)
```

`AuthorizationFilter` uses the configured `AuthorizationManager` to check whether the `Authentication`
for the current request, retrieved from the `SecurityContextHolder`, permits access to the request.
If not then an `AccessDeniedException` is thrown. This will be caught by the 
`ExceptionTranslationFilter` and that will start the authentication process.

```
16:16:51.573 o.s.s.w.a.ExceptionTranslationFilter     : Sending AnonymousAuthenticationToken [Principal=anonymousUser, Credentials=[PROTECTED], Authenticated=true, Details=WebAuthenticationDetails [RemoteIpAddress=0:0:0:0:0:0:0:1, SessionId=81F31BBD3739ACAF5F3F7D17AB952FE1], Granted Authorities=[ROLE_ANONYMOUS]] to authentication entry point since access is denied
```

`ExceptionTranslationFilter` has caught the `AccessDeniedException` thrown by `AuthorizationFilter`
and is going to start the authentication flow by calling `AuthenticationEntryPoint#commence`

```
16:16:51.576 o.s.s.w.s.HttpSessionRequestCache        : Saved request http://localhost:8100/hello?continue to session
```

The request that will be resumed after authentication is saved to the session.

```
16:16:51.576 s.w.a.DelegatingAuthenticationEntryPoint : Match found! Executing org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint@70f60c62
```

The `DelegatingAuthenticationEntryPoint` compares the incoming request against configured 
`AuthenticationEntryPoint` implementations and finds `LoginUrlAuthenticationEntryPoint` as the 
match. 

```
16:16:51.576 o.s.s.web.DefaultRedirectStrategy        : Redirecting to http://localhost:8100/oauth2/authorization/keycloak
```

The `LoginUrlAuthenticationEntryPoint` uses `DefaultRedirectStrategy` to redirect to the internal
endpoint used for Keycloak. This is `http://localhost:8100/oauth2/authorization/keycloak`.

```
16:16:51.579 o.a.coyote.http11.Http11InputBuffer      : Received [GET /oauth2/authorization/keycloak HTTP/1.1
```

Here we're receiving the request from the browser as a result of the redirect. We won't show all the
`FilterChainProxy` interactions for this request, just the ones that match.

```
16:16:51.580 o.s.security.web.FilterChainProxy        : Invoking OAuth2AuthorizationRequestRedirectFilter (7/16)
```

The `OAuth2AuthorizationRequestRedirectFilter` uses a `OAuth2AuthorizationRequestResolver` to 
find from the request where the redirect should go.

```
16:16:51.581 o.s.s.web.DefaultRedirectStrategy        : Redirecting to http://localhost:8090/realms/MyAppRealm/protocol/openid-connect/auth?response_type=code&client_id=login&scope=openid&state=XWHAKQ0FdLWMYI9IOQzfIMewW7orTj_9GiuM0T0jZgs%3D&redirect_uri=http://localhost:8100/login/oauth2/code/keycloak&nonce=bM4K56Vtsgf0MzbPcktzVGF3LHWCXMIk5yFB3gOPUL0
```

Once the target for the redirect has been identified the `DefaultRedirectStrategy` sends the browser
there. The endpoint being redirected to is the `authorization_endpoint` found in the response to
the request to `.well-known/openid-configuration` made during startup. The `state` value passed as
a parameter here is checked against the `state` value returned in the GET redirect below.

```
16:17:01.521 o.a.coyote.http11.Http11InputBuffer      : Received [GET /login/oauth2/code/keycloak?state=XWHAKQ0FdLWMYI9IOQzfIMewW7orTj_9GiuM0T0jZgs%3D&session_state=6d2c5ee1-49a6-4f7f-bca1-865ac28c1fa4&code=5762c426-6a6c-4b0a-91a5-bd0eee6f0d60.6d2c5ee1-49a6-4f7f-bca1-865ac28c1fa4.3ef68ec7-9612-419e-b9f0-c59f08eae3a5 HTTP/1.1
```

After authentication Keycloak sends the browser a redirect to the url it has configured. Note 
matching `state` value. This is [step one](https://connect2id.com/learn/openid-connect#example-auth-code-flow-step-1)
in the authorization code flow.

```
16:17:01.522 o.s.security.web.FilterChainProxy        : Invoking OAuth2LoginAuthenticationFilter (8/16)
```

The incoming request is identified as an authentication request because it matches the 
configured `/login/oauth2/code/*` pattern. 

```
16:17:01.527 o.s.s.authentication.ProviderManager     : Authenticating request with OAuth2LoginAuthenticationProvider (1/4)
16:17:01.527 o.s.s.authentication.ProviderManager     : Authenticating request with OidcAuthorizationCodeAuthenticationProvider (2/4)
```

The ProviderManager tries configured AuthenticationProviders till it finds one that the successfully
processes the authentication request. The `OAuth2LoginAuthenticationProvider` does not process the
request but the `OidcAuthorizationCodeAuthenticationProvider` does.

```
16:17:01.533 o.s.web.client.RestTemplate              : HTTP POST http://localhost:8090/realms/MyAppRealm/protocol/openid-connect/token
16:17:01.533 o.s.web.client.RestTemplate              : Accept=[application/json, application/*+json]
16:17:01.536 o.s.web.client.RestTemplate              : Writing [{grant_type=[authorization_code], code=[5762c426-6a6c-4b0a-91a5-bd0eee6f0d60.6d2c5ee1-49a6-4f7f-bca1-865ac28c1fa4.3ef68ec7-9612-419e-b9f0-c59f08eae3a5], redirect_uri=[http://localhost:8100/login/oauth2/code/keycloak]}] as "application/x-www-form-urlencoded;charset=UTF-8"
```

Now a post is made to the Keycloak server to exchange the code received in browser redirect for an
id token. This is [step two](https://connect2id.com/learn/openid-connect#example-auth-code-flow-step-2)
in the authorization code flow. The response is

```json
{
  "access_token": "<access_token>",
  "expires_in": 300,
  "refresh_expires_in": 1800,
  "refresh_token": "<refresh_token>Y",
  "token_type": "Bearer",
  "id_token": "<id_token>",
  "not-before-policy": 0,
  "session_state": "6d2c5ee1-49a6-4f7f-bca1-865ac28c1fa4",
  "scope": "openid email profile"
}
```

From the OpenId Connect standards the `id_token` is a JWT and must be validated. The `access_token`
is a bearer token to use for fetching the user info.

```
16:17:01.590 o.s.web.client.RestTemplate              : HTTP GET http://localhost:8090/realms/MyAppRealm/protocol/openid-connect/certs
```

This is the request made to Keycloak to fetch the certificates needed to authenticate the JWT. The 
endpoint is part of the configuration retrieved from Keycloak when the app starts. Once the JWT is
authenticated a request is made to the `userinfo_endpoint`.

```
16:17:01.612 o.s.web.client.RestTemplate              : HTTP GET http://localhost:8090/realms/MyAppRealm/protocol/openid-connect/userinfo
```

The `access_token` from the response above is used as the Bearer token. This is the 
[claims](https://connect2id.com/learn/openid-connect#claims) step in the OpenID Connect process.

```
16:17:01.620 c.z.c.s.KeycloakGrantedAuthoritiesMapper : grantedAuthorities Optional[[ROLE_default-roles-myapprealm, ROLE_offline_access, ROLE_uma_authorization, ROLE_user]]
```

The [KeycloakGrantedAuthoritiesMapper](src/main/java/com/zanthan/client/security/KeycloakGrantedAuthoritiesMapper.java)
set in `SecurityConfig` converts the raw authorities from Keycloak into the `ROLE_` prefixed ones 
expected by the `hasRole` authorization configuration. This is configured in 
[SecurityConfig](src/main/java/com/zanthan/client/security/SecurityConfig.java).

```
16:17:01.621 w.c.HttpSessionSecurityContextRepository : Stored SecurityContextImpl [Authentication=OAuth2AuthenticationToken [Principal=Name: [alfred@bob.com], ....
```

After successful authentication the `AbstractAuthenticationProcessingFilter` superclass of 
`OAuth2LoginAuthenticationFilter` stores the security context for use by the thread using 
`SecurityContextHolderStrategy` and persists it using `HttpSessionSecurityContextRepository`.

```
16:17:01.622 o.s.s.web.DefaultRedirectStrategy        : Redirecting to http://localhost:8100/hello?continue
```

The configured `AuthenticationSuccessHandler` used by `AbstractAuthenticationProcessingFilter` is a
`SavedRequestAwareAuthenticationSuccessHandler` which redirects the browser to the URL stored in the
`HttpSessionRequestCache`.

```
16:17:01.625 o.a.coyote.http11.Http11InputBuffer      : Received [GET /hello?continue HTTP/1.1
```

Here's the request from the browser. The same processing flow through the `FilterChainProxy` occurs.

```
16:17:01.626 o.s.security.web.FilterChainProxy        : Invoking AuthorizationFilter (16/16)
```

The `AuthorizationFilter` uses `RequestMatcherDelegatingAuthorizationManager` to authorize.

```
16:17:01.626 RequestMatcherDelegatingAuthorizationManager : Checking authorization on SecurityContextHolderAwareRequestWrapper[ org.springframework.security.web.header.HeaderWriterFilter$HeaderWriterRequest@7c047fc0] using AuthorityAuthorizationManager[authorities=[ROLE_user]]
```

The `AuthorityAuthorizationManager` is used to check authorization. It's created from the 
configuration with the authorities that must be present and these are checked against the 
authorities retrieved from the context. The manager is passed a supplier so fetching the
authorities happens next. 

```
16:17:01.626 w.c.HttpSessionSecurityContextRepository : Retrieved SecurityContextImpl [Authentication=OAuth2AuthenticationToken [Principal=Name: [alfred@bob.com], ....
```

When the `AnonymousAuthenticationFilter` was executed it set itself as a wrapper round the 
deferredContext in the security context holder so that it could return an anonymous authentication
if there isn't one in the holder.

```
16:17:01.627 o.s.s.w.a.AnonymousAuthenticationFilter  : Did not set SecurityContextHolder since already authenticated OAuth2AuthenticationToken [Principal=Name: [alfred@bob.com], ...
```

This is `AnonymousAuthenticationFilter` reporting that it didn't have to set an anonymous 
authentication.

```
16:17:01.627 o.s.security.web.FilterChainProxy        : Secured GET /hello?continue
```

Successfully made it through the security flow.

## Logout Flow

Starts with pressing the `Logout` button on the hello page.

```
18:49:30.980-05:00 o.a.coyote.http11.Http11InputBuffer      : Received [POST /logout HTTP/1.1
```

The app receives the post from the form.

```
18:49:30.987-05:00 o.s.security.web.FilterChainProxy        : Invoking LogoutFilter (6/15)
18:49:30.987 w.c.HttpSessionSecurityContextRepository : Retrieved SecurityContextImpl [Authentication=OAuth2AuthenticationToken [Principal=Name: [alfred@bob.com], 
18:49:30.987 o.s.s.w.a.logout.LogoutFilter            : Logging out [OAuth2AuthenticationToken [Principal=Name: [alfred@bob.com], 
```

The logout filter recognizes the `/logout` path. It retrieves the `Authentication` from the 
security context.

```
18:49:30.987 c.z.c.security.KeycloakLogoutHandler     : User alfred@bob.com has [ROLE_user,
```

The `LogoutFilter` is configured with a `CompositeLogoutHander`. The first is the logout handler 
configured in [SecurityConfig](src/main/java/com/zanthan/client/security/SecurityConfig.java).
It's going to perform the logout from Keycloak.

```
18:49:31.002 o.s.web.client.RestTemplate              : HTTP GET http://localhost:8090/realms/MyAppRealm/protocol/openid-connect/logout?id_token_hint=
```

A GET request is sent to the logout endpoint.

```
18:49:31.063 o.s.web.client.RestTemplate              : Response 200 OK
```

Keycloak responds with OK 

```
18:49:31.064 c.z.c.security.KeycloakLogoutHandler     : Successfully logged out from keycloak.
18:49:31.064o.s.s.w.a.l.SecurityContextLogoutHandler : Invalidated session 
```

The `KeycloakLogoutHandler` completes and the next logout handler, `SecurityContextLogoutHandler`
invalidates the session. 

```
18:49:31.064 .s.s.w.a.l.SimpleUrlLogoutSuccessHandler : Using default url /
18:49:31.064 o.s.s.web.DefaultRedirectStrategy        : Redirecting to /
```

After the logout handlers have processed the request the `LogoutSuccessHandler` is invoked. Here it's
a `SimpleUrlLogoutSuccessHandler` that redirects to `/`.

```
18:49:31.067 o.a.coyote.http11.Http11InputBuffer      : Received [GET / HTTP/1.1
```

The GET request is received from the browser and processing continues to show the `/` page, which
does not require authentication.