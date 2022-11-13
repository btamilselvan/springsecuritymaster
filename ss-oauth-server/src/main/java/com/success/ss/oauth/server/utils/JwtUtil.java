package com.success.ss.oauth.server.utils;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

@Component
public class JwtUtil {

  @Autowired private RSAPublicKey publicKey;

  @Autowired private RSAPrivateKey privateKey;

  public String createJwt(String subject) {
    JWTCreator.Builder jwtBuilder = JWT.create().withSubject(subject);
    Map<String, String> claims = new HashMap<>();
    claims.put("Claim1", "Claim1");
    claims.forEach(jwtBuilder::withClaim);
    Calendar cal = Calendar.getInstance();
    cal.add(Calendar.DAY_OF_MONTH, 1);
    return jwtBuilder
        .withNotBefore(new Date())
        .withExpiresAt(cal.getTime())
        .withIssuer("http://kmauth-server:8080")
        .sign(Algorithm.RSA256(publicKey, privateKey));
  }

  public Map<String, Object> getKey() {
    RSAKey key = new RSAKey.Builder(publicKey).build();
    return new JWKSet(key).toJSONObject();
  }
}
