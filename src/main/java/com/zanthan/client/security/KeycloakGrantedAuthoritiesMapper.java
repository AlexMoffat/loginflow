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

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.stereotype.Component;

@Component
public class KeycloakGrantedAuthoritiesMapper implements GrantedAuthoritiesMapper {
  
  private static final Logger log = LoggerFactory.getLogger(KeycloakGrantedAuthoritiesMapper.class);

  private static final String ROLES = "roles";
  
  @Override
  public Collection<? extends GrantedAuthority> mapAuthorities(
      Collection<? extends GrantedAuthority> authorities) {
    
    final Optional<Collection<GrantedAuthority>> grantedAuthorities = 
        authorities.stream()
            .filter(OidcUserAuthority.class::isInstance)
            .findFirst()
            .map(OidcUserAuthority.class::cast)
            .map(this::extractClaims)
            .map(this::convertClaims)
            .filter(Predicate.not(Collection::isEmpty));
    log.debug("grantedAuthorities {}", grantedAuthorities);
    return grantedAuthorities.isPresent() ? grantedAuthorities.get() : authorities;
  }
  
  private Collection<String> extractClaims(OidcUserAuthority userAuthority) {
    // In Keycloak we configured the mapper to add the roles to the userinfo with the claim name
    // of 'roles'.
    final var userInfo = userAuthority.getUserInfo();
    if (userInfo.hasClaim(ROLES)) {
      return userInfo.getClaimAsStringList(ROLES);
    } else {
      return List.of();
    }
  }
  
  private Collection<GrantedAuthority> convertClaims(Collection<String> claims) {
    return claims.stream()
        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
        .collect(Collectors.toList());
  }
}
