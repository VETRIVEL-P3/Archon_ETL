/**
 * 
 */
package com.p3solutions.archon_authentication_service.core.authentication.security.jwt.exceptions;

import org.springframework.security.core.AuthenticationException;

/**
 * @author saideepak
 *
 */
public class AuthException extends AuthenticationException {

	/**
	 * 
	 */
	private static final long serialVersionUID = -4409236508486837265L;

	/**
	 * @param msg
	 */
	public AuthException(String msg) {
		super(msg);
	}
	
	public AuthException(String msg, Throwable t) {
		super(msg, t);
	}

}
