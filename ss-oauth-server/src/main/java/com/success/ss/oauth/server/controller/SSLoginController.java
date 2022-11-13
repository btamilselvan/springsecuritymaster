package com.success.ss.oauth.server.controller;

import java.security.Principal;
import java.time.Instant;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.success.ss.oauth.server.utils.JwtUtil;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/")
@Slf4j
public class SSLoginController {

  @Autowired private JwtUtil jwtUtil;

  @GetMapping("/m1")
  public String methodOne(Principal user) {
    log.info("inside method one {}", user.getName());
    return "Current time is " + Instant.now().toString();
  }

  @GetMapping("/home")
  public String methodTwo() {
    log.info("inside method home {}");
    return "Welcome home...Current time is " + Instant.now().toString();
  }

  @GetMapping("/kmlogin")
  public String login() {
    log.info("inside login one ");
    String jwt = jwtUtil.createJwt("Test User");
    log.info("jwt {}", jwt);
    return jwt;
  }

  /*@GetMapping("/.well-known/km-auth-server/oauth2/jwks")
  @ResponseBody
  public Map<String, Object> getKey() {
    log.info("return public key");
    return jwtUtil.getKey();
  }*/

}
