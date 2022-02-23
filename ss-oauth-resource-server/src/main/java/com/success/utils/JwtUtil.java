package com.success.utils;

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
import com.auth0.jwt.algorithms.Algorithm;

@Component
public class JwtUtil {

  @Autowired private RSAPublicKey publicKey;

  @Autowired private RSAPrivateKey privateKey;

  public String createJwt() {
    JWTCreator.Builder jwtBuilder = JWT.create().withSubject("TEST Subject");
    Map<String, String> claims = new HashMap<>();
    claims.put("Claim1", "Claim1");
    //    claims.forEach((key, value) -> jwtBuilder.withClaim(key, value));
    claims.forEach(jwtBuilder::withClaim);
    Calendar cal = Calendar.getInstance();
    cal.add(Calendar.DAY_OF_MONTH, 1);
    return jwtBuilder
        .withNotBefore(new Date())
        .withExpiresAt(cal.getTime())
        .sign(Algorithm.RSA256(publicKey, privateKey));
  }
}
