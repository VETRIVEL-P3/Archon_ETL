package com.p3solutions.archon_authentication_service.core.user.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.BAD_REQUEST, code = HttpStatus.BAD_REQUEST, reason = "Invalid Model ID")
public class InvalidModelException extends RuntimeException {
	/**
	 * 
	 */
	private static final long serialVersionUID = -9092341739043840812L;

	public InvalidModelException(String message) {
		super(message);
	}
}
