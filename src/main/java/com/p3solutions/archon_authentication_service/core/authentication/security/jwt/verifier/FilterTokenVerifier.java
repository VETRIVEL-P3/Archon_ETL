package com.p3solutions.archon_authentication_service.core.authentication.security.jwt.verifier;

import org.springframework.stereotype.Component;

@Component
public class FilterTokenVerifier implements TokenVerifier {
  @Override
  public boolean verify(String jti) {
    return true;
  }
}
