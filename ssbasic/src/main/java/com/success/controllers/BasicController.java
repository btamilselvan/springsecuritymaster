package com.success.controllers;

import java.security.Principal;
import java.time.Instant;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/")
@Slf4j
public class BasicController {

  @Autowired private AuthenticationManager authManager;

  @GetMapping("/one")
  @Secured(value = "ROLE_USER1")
  public String secureMethod1(Principal user) {
    log.info("username is {}", SecurityContextHolder.getContext().getAuthentication().getName());
    return "Hello " + user.getName() + " " + Instant.now().toString();
  }

  @GetMapping("/two")
  @Secured(value = {"ROLE_USER", "ROLE_USER1"})
  public String secureMethod2(Principal user) {
    return secureMethod1(user);
  }

  @GetMapping("/three")
  public String secureMethod3(Principal user, HttpServletRequest request) {
    log.info("user name {}", request.getUserPrincipal().getName());
    return secureMethod1(user);
  }

  @GetMapping("/p/one")
  public String publicMethod1() {
    String username = "test";
    String password = "test123";
    UsernamePasswordAuthenticationToken token =
        new UsernamePasswordAuthenticationToken(username, password);
    Authentication result = authManager.authenticate(token);
    log.info("authenticated {}", result.isAuthenticated());
    log.info("public unprotected method");
    return "public method " + Instant.now().toString();
  }
}
