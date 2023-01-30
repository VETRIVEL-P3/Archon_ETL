package com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans;

import java.io.Serializable;

@FunctionalInterface
public interface JwtToken extends Serializable {
	String getToken();
}
