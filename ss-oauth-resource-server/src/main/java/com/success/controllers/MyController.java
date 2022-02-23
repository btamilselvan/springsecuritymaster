package com.success.controllers;

import java.security.Principal;
import java.time.Instant;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.success.utils.JwtUtil;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/")
@Slf4j
public class MyController {

  @Autowired private JwtUtil jwtUtil;

  @GetMapping("/m1")
  public String methodOne(Principal user) {
    log.info("inside method one {}", user.getName());
    return "Current time is " + Instant.now().toString();
  }

  @GetMapping("/login")
  public String login() {
    log.info("inside login one ");
    String jwt = jwtUtil.createJwt();
    log.info("jwt {}", jwt);
    return jwt;
  }

  private void addJWT(HttpServletResponse response) {}
}
