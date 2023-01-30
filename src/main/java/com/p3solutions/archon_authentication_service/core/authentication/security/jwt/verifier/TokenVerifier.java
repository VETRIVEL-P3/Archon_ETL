package com.p3solutions.archon_authentication_service.core.authentication.security.jwt.verifier;

public interface TokenVerifier {
    boolean verify(String jti);
}
