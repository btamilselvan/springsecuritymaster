package com.success.ss.oauth.server.config;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.extern.slf4j.Slf4j;
/**
 * keytool -genkey -alias my-jwt-sigining-key -keyalg RSA -keystore keystore.jks -keysize 4096
 * -keypass password -storepass password
 *
 * @author Tamil
 */
@Configuration
@Slf4j
public class JwtConfig {

  @Value("${jwt.keystore}")
  private String keystorePath;

  @Value("${jwt.keystore.password}")
  private String keystorePassword;

  @Value("${jwt.key.alias}")
  private String keyAlias;

  @Value("${jwt.privatekey.password}")
  private String privateKeyPassPhrase;

  @Bean
  public KeyStore keyStore() {
    KeyStore ks;
    try {
      ks = KeyStore.getInstance(KeyStore.getDefaultType());
      ks.load(
          Thread.currentThread().getContextClassLoader().getResourceAsStream(keystorePath),
          keystorePassword.toCharArray());
      return ks;
    } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
      log.error("unable to load keystore", e);
    }
    throw new IllegalArgumentException("keystore load failed");
  }

  @Bean
  public RSAPrivateKey rsaPrivateKey(KeyStore keystore) {
    // to sign the token
    try {
      Key key = keystore.getKey(keyAlias, privateKeyPassPhrase.toCharArray());
      if (key instanceof RSAPrivateKey) {
        return (RSAPrivateKey) key;
      }
    } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
      log.error("unable to load private key", e);
    }
    throw new IllegalArgumentException("unable to load private key");
  }

  @Bean
  public RSAPublicKey rsaPublicKey(KeyStore keystore) {
    // to decode the token
    try {
      Certificate cert = keystore.getCertificate(keyAlias);
      PublicKey pk = cert.getPublicKey();
      if (pk instanceof RSAPublicKey) {
        return (RSAPublicKey) pk;
      }
    } catch (KeyStoreException e) {
      log.error("unable to get publickey", e);
    }
    throw new IllegalArgumentException("unable to get publickey");
  }

  @Bean
  public JwtDecoder decoder(RSAPublicKey pk) {
    return NimbusJwtDecoder.withPublicKey(pk).build();
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey =
        new RSAKey.Builder(rsaPublicKey(keyStore()))
            .privateKey(rsaPrivateKey(keyStore()))
            .keyID(UUID.randomUUID().toString())
            .build();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
  }
}
