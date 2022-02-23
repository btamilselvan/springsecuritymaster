package com.success.services;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class CustomOAuthUserService extends DefaultOAuth2UserService {
  @Override
  public OAuth2User loadUser(OAuth2UserRequest userRequest) {
    log.info("userDetails Auth request {}", userRequest.toString());
    // instead of extending DefaultOAuth2UserService, we can also implement OAuth2UserService and
    // implement our own code
    log.info("before loading user details from Auth Provider");
    OAuth2User user = super.loadUser(userRequest);
    log.info("logged in user's email is {}", user.getAttribute("email").toString());
    log.info("after loading user details from Auth Provider");
    // do custom functionalities here. for e.g.  update the backend database about the logged in
    // user.
    return user;
  }
}
