package com.p3solutions.archon_authentication_service.core.authentication.security.jwt;

import lombok.Data;

@Data
public class JwtConfigParameters {

  private Integer tokenExpirationTime;
  private Integer refreshTokenExpTime;
  private String tokenIssuer;
  private String tokenSigningKey;
}
