package com.success.controllers;

import java.security.Principal;
import java.time.Instant;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/")
@Slf4j
public class UserDetailsController {

  @GetMapping("/one")
  public String secureMethod1(Principal user) {
    log.info("username is {}", SecurityContextHolder.getContext().getAuthentication().getName());
    return "Hello " + user.getName() + " " + Instant.now().toString();
  }

  @GetMapping("/two")
  public String secureMethod2(Principal user) {
    return secureMethod1(user);
  }
}
