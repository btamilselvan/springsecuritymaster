package com.success.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
@Profile("!custom-auth-provider")
public class BasicSecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    // this enables basic login
    //    http.httpBasic().and().authorizeRequests().anyRequest().authenticated();

    // this provides form login
    //    http.formLogin().and().authorizeRequests().anyRequest().authenticated();

    // remember-me implementation
    http.formLogin()
        .and()
        .authorizeRequests()
        .antMatchers("/p/**")
        .permitAll()
        .and()
        .authorizeRequests()
        .anyRequest()
        .authenticated()
        .and()
        .rememberMe()
        .key("my-remember-key-token")
        .rememberMeCookieName("remember-me")
        .rememberMeParameter("remember-me-param")
        .and()
        .logout()
        .deleteCookies("JSESSIONID");
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
        .withUser("test")
        .password(passwordEncoder().encode("test123")) // encode and store the password in memory
        .roles("USER")
        .and()
        .withUser("user1")
        .password(passwordEncoder().encode("test345"))
        .roles("USER1");
  }

  @Override
  @Bean
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Bean
  protected PasswordEncoder passwordEncoder() {
    // this has to be a bean, in order for spring to decode the password later
    return new BCryptPasswordEncoder();
  }
}
