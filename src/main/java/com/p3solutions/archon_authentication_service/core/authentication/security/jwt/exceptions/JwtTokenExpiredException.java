package com.p3solutions.archon_authentication_service.core.authentication.security.jwt.exceptions;

import org.springframework.security.core.AuthenticationException;

import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans.JwtAccessToken;

public class JwtTokenExpiredException extends AuthenticationException {
	private static final long serialVersionUID = -5959543783324224864L;

	private JwtAccessToken token;

	public JwtTokenExpiredException(String msg) {
		super(msg);
	}

	public JwtTokenExpiredException(JwtAccessToken token, String msg, Throwable t) {
		super(msg, t);
		this.token = token;
	}

	public String token() {
		return this.token.getToken();
	}
}
