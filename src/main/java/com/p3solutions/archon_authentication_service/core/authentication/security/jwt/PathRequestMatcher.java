package com.p3solutions.archon_authentication_service.core.authentication.security.jwt;

import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * PathRequestMatcher takes the string URL paths during initialisation
 * and confirms if the current request matches any of the defined paths.
 *
 * @author vishwabhat
 */
public class PathRequestMatcher implements RequestMatcher{
	private final OrRequestMatcher skipper; // matches any of the passed URL
	private final RequestMatcher processingMatcher;

	public PathRequestMatcher(List<String> pathsToSkip, String pathToProcess) {
		List<RequestMatcher> requestURLPathsToSkip = pathsToSkip.stream().map(AntPathRequestMatcher::new).collect(Collectors.toList());
		skipper = new OrRequestMatcher(requestURLPathsToSkip);
		processingMatcher = new AntPathRequestMatcher(pathToProcess);
	}

	@Override
	public boolean matches(HttpServletRequest request) {
        return !skipper.matches(request) // given request should not match in any of the given skip paths
                && processingMatcher.matches(request); // given request should fall under processing path
    }

}
