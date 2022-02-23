package com.success.controllers;

import java.security.Principal;
import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.success.utils.JwtUtil;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/")
@Slf4j
public class MyClientResourceServerController {

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

  @GetMapping("/login")
  public String login() {
    log.info("inside login one ");
    String jwt = jwtUtil.createJwt("Test User");
    log.info("jwt {}", jwt);
    return jwt;
  }
}
