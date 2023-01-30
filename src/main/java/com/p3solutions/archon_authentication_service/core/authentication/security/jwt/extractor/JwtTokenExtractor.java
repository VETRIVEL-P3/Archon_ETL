package com.p3solutions.archon_authentication_service.core.authentication.security.jwt.extractor;

import com.p3solutions.common_beans_dto.authentication.abstract_repository.TokenAbstractRespository;
import com.p3solutions.common_beans_dto.authentication.beans.TokenExpiryDetails;
import com.p3solutions.common_beans_dto.common_constants.FailureMessages;
import com.p3solutions.utility.common_exceptions.ServerException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * JwtTokenExtractor is used to extract token from the Header. For JWT
 * Authentication, application expects JWT Token to be attached in the header
 * with the following format: <br/>
 * <code> header key => "X-Authenticate", header value => "Bearer "+Jwt token </code>
 *
 * @author vishwabhat
 */
@Component
public class JwtTokenExtractor implements TokenExtractor {

	private static final String HEADER_PREFIX = "Bearer ";
	@Autowired
	private TokenAbstractRespository tokenModelAbstractRepository;

	@Override
	public String extract(HttpServletRequest request) {
		Cookie[] allCookies = request.getCookies();
		String token = "";
		if (allCookies != null) {
			for (Cookie cookie : allCookies) {
				if (cookie.getName().equalsIgnoreCase("accessToken")) {
					token = cookie.getValue();
					break;
				}
			}
		}
		if (StringUtils.isEmpty(token)) {
			String tokenPayload = request.getHeader("Authorization");
			if (!StringUtils.isEmpty(tokenPayload))
				token = tokenPayload.substring(HEADER_PREFIX.length());
		}

		if (StringUtils.isEmpty(token)) {
			throw new AuthenticationServiceException(FailureMessages.MISSING_AUTH_HEADER);
		}
		List<TokenExpiryDetails> tokenList = tokenModelAbstractRepository.findAll();
		if (tokenList != null) {
			for (TokenExpiryDetails detail : tokenList) {
				if (detail.getToken().equals(token)) {
					throw new ServerException("Token is expired");
				}
			}
		}
		return token;
	}

}
