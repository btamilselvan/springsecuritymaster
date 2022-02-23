package com.success.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;

import com.success.filters.MyAfterOAuthFilter;
import com.success.services.CustomOAuthUserService;

@Configuration
@EnableWebSecurity(debug = true)
public class OAuthClientSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired private CustomOAuthUserService userService;
  @Autowired private MyCustomOAuthRequestRepoisotry oauthRequestRepo;
  @Autowired private CustomOAuthuccessHandler authSuccessHandler;
  @Autowired private MyAfterOAuthFilter myFilter;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    /*http.cors()
    .and()
    .csrf()
    .disable()
    .authorizeRequests()
    .anyRequest()
    .authenticated()
    .and()
    .oauth2Login()
    .authorizationEndpoint()
    .authorizationRequestRepository(this.oauthRequestRepo)
    .and()
    .userInfoEndpoint()
    .userService(this.userService)
    .and()
    .successHandler(this.authSuccessHandler)
    .and()
    .sessionManagement()
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS);*/

    /*http.cors()
    .and()
    .csrf()
    .disable()
    .authorizeRequests()
    .anyRequest()
    .authenticated()
    .and()
    .oauth2Login()
    .userInfoEndpoint()
    .userService(this.userService)
    .and()
    .successHandler(this.authSuccessHandler);*/

    http.cors()
        .and()
        .csrf()
        .disable()
        .authorizeRequests()
        .anyRequest()
        .authenticated()
        .and()
        .oauth2Login()
        .userInfoEndpoint()
        .userService(this.userService)
        .and()
        .and()
        .addFilterAfter(myFilter, OAuth2LoginAuthenticationFilter.class);
  }
}
