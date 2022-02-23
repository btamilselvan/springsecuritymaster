package com.success.controllers;

import java.time.Instant;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/")
@Slf4j
public class OACRestController {

  @GetMapping("/m1")
  public String methodOne(@AuthenticationPrincipal OAuth2User user) {
    log.info("from method one. user name {}", user.getAttribute("name").toString());
    return "Hello " + user.getAttribute("name") + ", current time is:: " + Instant.now().toString();
  }
}
