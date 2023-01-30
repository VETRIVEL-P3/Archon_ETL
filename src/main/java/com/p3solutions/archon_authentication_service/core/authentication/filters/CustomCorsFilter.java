package com.p3solutions.archon_authentication_service.core.authentication.filters;

import org.owasp.encoder.Encode;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

public class CustomCorsFilter extends CorsFilter {

	public CustomCorsFilter() {
		super(configurationSource());
	}

	private static UrlBasedCorsConfigurationSource configurationSource() {
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true);
		config.addAllowedOrigin("*");
		config.addAllowedHeader("*");
		config.setMaxAge(36000L);
		config.setAllowedMethods(Arrays.asList("GET", "HEAD", "PATCH", "POST", "PUT", "DELETE"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		return source;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws ServletException, IOException {
		res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, PATCH");
		res.setHeader("Access-Control-Max-Age", "3600");
		res.setHeader("Access-Control-Allow-Origin", Encode.forJava(req.getHeader("Origin")));
		res.setHeader("Access-Control-Allow-Credentials", "true");
		res.setHeader("Access-Control-Allow-Headers",
				"X-PINGOTHER,Content-Type,X-Requested-With,accept,Origin,Access-Control-Request-Method,Access-Control-Request-Headers,Authorization");
		res.addHeader("Access-Control-Expose-Headers", "xsrf-token");
		if ("OPTIONS".equals(req.getMethod())) {
			res.setStatus(HttpServletResponse.SC_OK);
		} else {
			chain.doFilter(req, res);
		}
	}
}
