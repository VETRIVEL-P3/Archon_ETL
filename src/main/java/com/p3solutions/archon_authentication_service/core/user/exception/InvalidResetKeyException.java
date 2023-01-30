package com.p3solutions.archon_authentication_service.core.user.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.BAD_REQUEST, code = HttpStatus.BAD_REQUEST, reason = "Invalid or Expired Reset key")
public class InvalidResetKeyException extends RuntimeException {
	/**
	 * 
	 */
	private static final long serialVersionUID = -8595374450443135577L;

	public InvalidResetKeyException(String message) {
		super(message);
	}
}
