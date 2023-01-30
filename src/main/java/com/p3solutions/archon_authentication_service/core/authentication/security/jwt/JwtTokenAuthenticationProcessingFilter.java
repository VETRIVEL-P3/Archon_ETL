package com.p3solutions.archon_authentication_service.core.authentication.security.jwt;

import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans.JwtAccessToken;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.extractor.TokenExtractor;
import com.p3solutions.utility.common_exceptions.ServerException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JWT Token Authentication Processing Filter is applied to all the requests
 * except <code>
 * /api/auth/token</code> and <code>/api/auth/login</code> <br>
 * This entity has the following responsibilities: <br>
 * 1. Check for access token in the header with the key:
 * <code> X-Authorization </code>. If found then delegate authentication to
 * {@link JwtAuthenticationProvider} otherwise throw
 * {@link AuthenticationException} <br>
 * 2. Calls success or failure strategies based on the outcome of authentication
 * process performed by {@link JwtAuthenticationProvider} <br>
 *
 * @author vishwabhat
 * @see JwtAuthenticationProvider
 */
public class JwtTokenAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {
	private static final String AUTHENTICATION_HEADER_NAME = "Authorization";
	private AuthenticationFailureHandler failureHandler;
	private TokenExtractor tokenExtractor;

	public JwtTokenAuthenticationProcessingFilter(
			@Qualifier("jwtFailureHandler") AuthenticationFailureHandler failureHandler, TokenExtractor tokenExtractor,
			RequestMatcher matcher) {
		super(matcher);
		this.failureHandler = failureHandler;
		this.tokenExtractor = tokenExtractor;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
		final String token = tokenExtractor.extract(request);
		return getAuthenticationManager().authenticate(new JwtSpringAuthenticationToken(new JwtAccessToken(token)));
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authResult);
		SecurityContextHolder.setContext(context);
		chain.doFilter(request, response);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		SecurityContextHolder.clearContext();
		throw new ServerException("Token is expired");
		//failureHandler.onAuthenticationFailure(request, response, failed);

	}
}
