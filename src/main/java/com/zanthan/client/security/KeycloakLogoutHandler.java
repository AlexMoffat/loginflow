/**
 * Copyright 2023 Alex Moffat
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.zanthan.client.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class KeycloakLogoutHandler implements LogoutHandler {

  private static final Logger logger = LoggerFactory.getLogger(KeycloakLogoutHandler.class);

  /**
   * From the Keycloak documentation at https://www.keycloak.org/docs/latest/securing_apps/index.html#logout
   */
  private static final String logoutPath = "/protocol/openid-connect/logout";
  
  private final RestTemplate restTemplate;

  public KeycloakLogoutHandler(RestTemplate restTemplate) {
    this.restTemplate = restTemplate;
  }

  @Override
  public void logout(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) {
    logger.info("User {} has {}", authentication.getName(), authentication.getAuthorities());
    logoutFromKeycloak((OidcUser) authentication.getPrincipal());
  }
  
  private void logoutFromKeycloak(OidcUser user) {
    logger.info("User {}", user);
    final String endSessionEndpoint = user.getIssuer() + logoutPath;
    final String logoutUri = UriComponentsBuilder
        .fromUriString(endSessionEndpoint)
        .queryParam("id_token_hint", user.getIdToken().getTokenValue())
        .toUriString();
    
    final ResponseEntity<String> logoutResponse = 
        restTemplate.getForEntity(logoutUri, String.class);
    if (logoutResponse.getStatusCode().is2xxSuccessful()) {
      logger.info("Successfully logged out from keycloak.");
    } else {
      logger.error("Could not propagate {} logout to Keycloak", user.getName());
    }
  }
}
