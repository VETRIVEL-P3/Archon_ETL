package com.p3solutions.archon_authentication_service.core.constants;

import io.jsonwebtoken.SignatureAlgorithm;

public final class JwtConstants {
  private JwtConstants() {
    throw new UnsupportedOperationException();
  }

  public static class ApiResponseFields {
    private ApiResponseFields() {}
    public static final String USER = "user";
    public static final String ACCESS_TOKEN = "accessToken";
    public static final String REFRESH_TOKEN = "refreshToken";
    public static final String ROLES = "roles";
    public static final String LICENSE_EXPIRED = "licenseExpired";
  }

  public static final String REFRESH_TOKEN_ROLE = "REFRESH_TOKEN";

  public static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS512;
}
