package com.success.configs;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import com.success.utils.CookieUtils;
import com.success.utils.JwtUtil;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class CustomOAuthuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

  @Autowired private JwtUtil jwtUtil;

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    log.info("success.......");
    log.info("redirect_uri from original request {}", request.getParameter("redirect_uri"));
    String targetUrl = determineTargetUrl(request, response, authentication);
    log.info("taregt url is {} ", targetUrl);
    getRedirectStrategy().sendRedirect(request, response, targetUrl);
  }

  @Override
  protected String determineTargetUrl(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    Optional<String> redirectUri =
        CookieUtils.getCookie(
                request, MyCustomOAuthRequestRepoisotry.REDIRECT_URI_PARAM_COOKIE_NAME)
            .map(Cookie::getValue);

    String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

    String token = jwtUtil.createJwt(authentication.getName());
    response.setHeader("Authorization", "Bearer " + token);

    return UriComponentsBuilder.fromUriString(targetUrl)
        .queryParam("token", token)
        .build()
        .toUriString();
  }
}
