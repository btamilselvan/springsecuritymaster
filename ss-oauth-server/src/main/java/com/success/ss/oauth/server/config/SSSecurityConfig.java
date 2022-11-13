package com.success.ss.oauth.server.config;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration
@EnableWebSecurity(debug = true)
public class SSSecurityConfig {

  @Value("${user.oauth.clientId}")
  private String clientId;

  @Value("${user.oauth.clientSecret}")
  private String clientSecret;

  // use this method if we don't want to enable oauth server capabilities. but implement the
  // /.well-known/km-auth-server/oauth2/jwks method for resource server to get the JWT public key
  
  //http://localhost:8080/.well-known/oauth-authorization-server
  /*@Bean
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

    http.cors()
        .and()
        .csrf()
        .disable()
        .authorizeRequests()
        .antMatchers("/actuator/mappings", "/home", "/kmlogin", "/.well-known/km-auth-server/oauth2/jwks")
        .permitAll()
        .and()
        .authorizeRequests(authorize -> authorize.anyRequest().authenticated())
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .oauth2ResourceServer()
        .jwt();

    http.exceptionHandling(
        exceptions -> exceptions.authenticationEntryPoint(new Http403ForbiddenEntryPoint()));
    return http.build();
  }*/

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
      throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    // return 401 for unauthenticated requests
    http.exceptionHandling(
        exceptions ->
            exceptions.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));

    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

    http.cors()
        .and()
        .csrf()
        .disable()
        .authorizeRequests()
        .antMatchers("/actuator/mappings", "/home", "/kmlogin")
        .permitAll()
        .and()
        .authorizeRequests(authorize -> authorize.anyRequest().authenticated())
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .oauth2ResourceServer() // this KMLoginService is also a resource server.
        .jwt();
    return http.build();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    // our custom oauth client configuration.
    // no scopes specified here.
    // redirectUri is just a placeholder uri
    // Login using /kmlogin end-point, obtain the JWT and send it in the auth header.
    // implement the necessary oauth endpoints (e.g. /.well-known/km-auth-server/oauth2/jwks)
    RegisteredClient registeredClient =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientSecret(clientSecret)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            // just a dummy value. No oauth workflow will be initiated by the clients
            .redirectUri("http://localhost:8080/authorized")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
            .build();
    return new InMemoryRegisteredClientRepository(registeredClient);
  }
  // ---------------------------------------------------------------------------------------
  /*
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    return http.formLogin(Customizer.withDefaults()).csrf().disable().build();
  }

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

    http.cors()
        .and()
        .csrf()
        .disable()
        .authorizeRequests()
        .antMatchers("/actuator/**", "/home", "/kmlogin")
        .permitAll()
        .and()
        .authorizeRequests(authorize -> authorize.anyRequest().authenticated())
        .formLogin(Customizer.withDefaults());
    return http.build();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient registeredClient =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientSecret(clientSecret)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            // allowed redirect URLs that the clients may use
            .redirectUri("http://127.0.0.1:8082/login/oauth2/code/km-client-oidc")
            .redirectUri("http://127.0.0.1:8082/authorized")
            .scope(OidcScopes.OPENID)
            .scope("articles.read")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .build();

    return new InMemoryRegisteredClientRepository(registeredClient);
  }

  @Bean
  public InMemoryUserDetailsManager userDetailsService(PasswordEncoder passwordEncoder) {
    UserDetails user =
        User.withUsername("user")
            .password(passwordEncoder.encode("password"))
            .roles("USER")
            .build();

    UserDetails admin =
        User.withUsername("admin")
            .password(passwordEncoder.encode("admin"))
            .roles("USER", "ADMIN")
            .build();

    return new InMemoryUserDetailsManager(user, admin);
  }
  // ---------------------------------------------------------------------------------------
  /*  @Bean
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

    http.cors()
        .and()
        .csrf()
        .disable()
        .authorizeRequests()
        .antMatchers("/actuator/mappings", "/home", "/kmlogin")
        .permitAll()
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeRequests(authorize -> authorize.anyRequest().authenticated())
        .oauth2ResourceServer() // this KMLoginService is also a resource server.
        .jwt();

    http.exceptionHandling(
        exceptions ->
            exceptions.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
    return http.build();
  }

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    return http.csrf().disable().build();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient registeredClient =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientSecret(clientSecret)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            // allowed redirect URLs that the clients may use
            .redirectUri("http://127.0.0.1:8082/login/oauth2/code/km-client-oidc")
            .redirectUri("http://127.0.0.1:8082/authorized")
            .scope(OidcScopes.OPENID)
            .scope("articles.read")
            .build();

    return new InMemoryRegisteredClientRepository(registeredClient);
  }*/

  @Bean
  public PasswordEncoder getPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public ProviderSettings providerSettings() {
    return ProviderSettings.builder().issuer("http://kmauth-server:8080").build();
  }
}
