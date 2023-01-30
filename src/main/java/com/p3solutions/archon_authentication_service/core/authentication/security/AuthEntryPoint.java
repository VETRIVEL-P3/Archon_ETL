package com.p3solutions.archon_authentication_service.core.authentication.security;

import com.p3solutions.common_beans_dto.common_constants.FailureMessages;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class AuthEntryPoint implements AuthenticationEntryPoint {

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex)
			throws IOException {
		response.sendError(HttpStatus.UNAUTHORIZED.value(), FailureMessages.FORBIDDEN_MESSAGE);
	}
}
