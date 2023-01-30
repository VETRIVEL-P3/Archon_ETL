package com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

import java.util.List;
import java.util.Optional;

@SuppressWarnings("unchecked")
public class JwtRefreshToken implements JwtToken {
  /**
	 * 
	 */
	private static final long serialVersionUID = 2408070537438444998L;
private Jws<Claims> claims;

  private JwtRefreshToken(Jws<Claims> claims) {
    this.claims = claims;
  }

  /** Creates and validates Refresh token */
  public static Optional<JwtRefreshToken> create(JwtAccessToken token, String signingKey) {
    Jws<Claims> claims = token.parseClaims(signingKey);

    List<String> roles = claims.getBody().get("roles", List.class);
    if (roles == null || roles.isEmpty() || roles.stream().noneMatch("REFRESH_TOKEN"::equals)) {
      return Optional.empty();
    }

    return Optional.of(new JwtRefreshToken(claims));
  }

  @Override
  public String getToken() {
    return null;
  }

  public Jws<Claims> getClaims() {
    return claims;
  }

  public String getJti() {
    return claims.getBody().getId();
  }

  public String getSubject() {
    return claims.getBody().getSubject();
  }
}
