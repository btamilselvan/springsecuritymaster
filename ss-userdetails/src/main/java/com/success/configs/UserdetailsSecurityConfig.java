package com.success.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.success.services.MyUserDetailsService;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class UserdetailsSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired private MyUserDetailsService userDetailsService;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    // this enables basic login
    //    http.httpBasic().and().authorizeRequests().anyRequest().authenticated();

    // this provides form login
    http.formLogin().and().authorizeRequests().anyRequest().authenticated();
    http.csrf().disable();
    http.headers().frameOptions().disable(); //for h2-console
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
  }

  //  protected

  @Bean
  protected PasswordEncoder passwordEncoder() {
    // this has to be a bean, in order for spring to decode the password later
    return new BCryptPasswordEncoder();
  }
}
