package com.success.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;

import com.success.filters.MyAfterAuthFilter;

@Configuration
@EnableWebSecurity(debug = true)
public class OAuthClientResourceServerSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired private MyCustomOAuthRequestRepoisotry oauthRequestRepo;
  @Autowired private CustomOAuthuccessHandler authSuccessHandler;
  @Autowired private MyAfterAuthFilter myFilter;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.cors()
        .and()
        .csrf()
        .disable()
        .authorizeRequests()
        .antMatchers("/oauth2/**", "/home", "/login")
        .permitAll()
        .and()
        .authorizeRequests()
        .anyRequest()
        .authenticated()
        .and()
        .oauth2Login()
        .authorizationEndpoint()
        .authorizationRequestRepository(this.oauthRequestRepo)
        .and()
        .successHandler(this.authSuccessHandler)
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .oauth2ResourceServer()
        .jwt()
        .and()
        .and()
        .addFilterAfter(myFilter, BearerTokenAuthenticationFilter.class);
    // adding oauth2ResourceServer() will enable oauth capabilities and add the
    // BearerTokenAuthenticationFilter to the filter chain.
    
  }
}
