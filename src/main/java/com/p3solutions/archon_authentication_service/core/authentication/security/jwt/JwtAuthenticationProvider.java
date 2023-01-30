/**
 * 
 */
package com.p3solutions.archon_authentication_service.core.authentication.security.jwt;

import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.JwtTokenGenerator.UserInfo;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans.JwtAccessToken;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.exceptions.AuthException;
import com.p3solutions.archon_authentication_service.core.constants.JwtConstants;
import com.p3solutions.common_beans_dto.authentication.abstract_repository.AuthUserDetailsAbstractRepository;
import com.p3solutions.common_beans_dto.authentication.beans.AuthUserDetails;
import com.p3solutions.common_beans_dto.common_constants.FailureMessages;
import com.p3solutions.utility.common_exceptions.ServerException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author saideepak
 *
 */
@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

	@Autowired
	private AuthUserDetailsAbstractRepository authUserDetailsAbstractRepository;

	/**
	 * Signing Key used to sign JWT token signatures
	 */
	@Value("${jwt.token.signing-key}")
	private String tokenSigningKey;

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.authentication.AuthenticationProvider#
	 * authenticate(org.springframework.security.core.Authentication)
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (authentication == null) {
			throw new AuthException(FailureMessages.MISSING_METHOD_PARAMETER.apply("authentication"));
		}
		JwtAccessToken jwtAccessToken = (JwtAccessToken) authentication.getCredentials();
		Jws<Claims> jwsClaims = jwtAccessToken.parseClaims(tokenSigningKey);
		String subject = extractSubjectFromClaims(jwsClaims); // user email-address
		List<GrantedAuthority> authorities = extractAuthoritiesFromClaims(jwsClaims);
		UserInfo userInfo = extractUserDetailsFromClaims(jwsClaims);

		final AuthUserDetails authUserDetails =  authUserDetailsAbstractRepository.loadUserByUsername(subject);
//		final Collection<? extends GrantedAuthority> authoritiesOnDb = mongoAuthUserDetails.getAuthorities();
//
//		// If roles present in the token and DB are not same
//		if (authorities.size() != authoritiesOnDb.size() || !authorities.containsAll(authoritiesOnDb)) {
//			throw new JwtTokenExpiredException(FailureMessages.JWT_TOKEN_ROLES_CHANGED);
//		}
		return new JwtSpringAuthenticationToken(authUserDetails, authorities);
	}

	// extracts subject from claims
	private String extractSubjectFromClaims(Jws<Claims> jwsClaims) {
		return jwsClaims.getBody().getSubject();
	}

	/**
	 * Extract User-details from Claims
	 * 
	 * @param jwsClaims
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private UserInfo extractUserDetailsFromClaims(Jws<Claims> jwsClaims) {
		LinkedHashMap<String, String> userDetails = jwsClaims.getBody().get(JwtConstants.ApiResponseFields.USER,
				LinkedHashMap.class);
		ServerException.throwIfTrue(userDetails == null, FailureMessages.JWT_TOKEN_INVALID);
		UserInfo userInfo = new UserInfo();
		userInfo.setFirstName(userDetails.get("firstName"));
		userInfo.setFirstName(userDetails.get("lastName"));
		userInfo.setFirstName(userDetails.get("id"));
		userInfo.setFirstName(userDetails.get("emailAddress"));

		return userInfo;
	}

	/**
	 * Extract authorities/roles from JWT claims
	 * 
	 * @param jwsClaims
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private List<GrantedAuthority> extractAuthoritiesFromClaims(Jws<Claims> jwsClaims) {
		List<LinkedHashMap<String, String>> rawScopes = jwsClaims.getBody().get(JwtConstants.ApiResponseFields.ROLES,
				List.class);
		ServerException.throwIfTrue(rawScopes == null, FailureMessages.JWT_NO_AUTHORITIES_TO_EXTRACT);
		return rawScopes.stream().map(scope -> (String) scope.get(JwtTokenGenerator.RoleInfo.Fields.roleName.name()))
				.map(SimpleGrantedAuthority::new).collect(Collectors.toList());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.springframework.security.authentication.AuthenticationProvider#supports(
	 * java.lang.Class)
	 */
	@Override
	public boolean supports(Class<?> authentication) {
		return (JwtSpringAuthenticationToken.class.isAssignableFrom(authentication));
	}

}
