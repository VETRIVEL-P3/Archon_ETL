package com.p3solutions.archon_authentication_service.core.authentication.security.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.p3solutions.common_beans_dto.common_beans.ApplicationResponseFailure;
import com.p3solutions.common_beans_dto.common_constants.FailureMessages;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * This handler handles in the event of user accessing forbidden APIs
 *
 * @author vishwabhat
 */
@Component
public class AuthorizationFailureHandler implements AccessDeniedHandler {

	private final ObjectMapper mapper;

	public AuthorizationFailureHandler(ObjectMapper mapper) {
		this.mapper = mapper;
	}

	/**
	 * Handles an access denied failure.
	 *
	 * @param request
	 *            that resulted in an <code>AccessDeniedException</code>
	 * @param response
	 *            so that the user agent can be advised of the failure
	 * @param accessDeniedException
	 *            that caused the invocation
	 * @throws IOException
	 *             in the event of an IOException
	 */
	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException {
		final ApplicationResponseFailure failureResponse = ApplicationResponseFailure.failure(FailureMessages.FORBIDDEN_MESSAGE,
				HttpStatus.FORBIDDEN);
		response.setStatus(failureResponse.getStatus());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		mapper.writeValue(response.getWriter(), failureResponse);
	}
}
