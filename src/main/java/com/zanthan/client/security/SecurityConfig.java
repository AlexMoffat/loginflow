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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private final KeycloakGrantedAuthoritiesMapper authoritiesMapper;
  private final KeycloakLogoutHandler logoutHandler;

  public SecurityConfig(
      KeycloakGrantedAuthoritiesMapper authoritiesMapper,
      KeycloakLogoutHandler logoutHandler
  ) {
    this.authoritiesMapper = authoritiesMapper;
    this.logoutHandler = logoutHandler;
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http
        // Access to '/hello' requires the 'user' role.
        .authorizeHttpRequests(authorizeRequests ->
            authorizeRequests
                .requestMatchers("/hello").hasRole("user")
                .anyRequest().permitAll())
        // Create the authorities checked by `hasRole` from the user info.
        .oauth2Login(loginConfig -> loginConfig.userInfoEndpoint(infoConfig ->
            infoConfig.userAuthoritiesMapper(authoritiesMapper)))
        // Logout from Keycloak when logging out of the app.
        .logout(logoutConfig ->
            logoutConfig
                .addLogoutHandler(logoutHandler)
                .logoutSuccessUrl("/"))
        .build();
  }
}
