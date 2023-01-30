/**
 * 
 */
package com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans;

import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.exceptions.JwtTokenExpiredException;
import io.jsonwebtoken.*;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;

import static com.p3solutions.common_beans_dto.common_constants.FailureMessages.JWT_TOKEN_EXPIRED;
import static com.p3solutions.common_beans_dto.common_constants.FailureMessages.JWT_TOKEN_INVALID;

/**
 * @author saideepak
 *
 */
public class JwtAccessToken implements JwtToken {

	/**
	 * 
	 */
	private static final long serialVersionUID = 4727871844167217888L;

	private static Logger logger = LoggerFactory.getLogger(JwtAccessToken.class);

	@Getter
	@Setter
	private String token;

	public JwtAccessToken(String token) {
		this.token = token;
	}

	/** Parses and validates JWT Token signature. */
	public Jws<Claims> parseClaims(String signingKey) {
		try {
			return Jwts.parser().setSigningKey(signingKey).parseClaimsJws(this.token);
		} catch (SignatureException | UnsupportedJwtException | MalformedJwtException | IllegalArgumentException ex) {
			logger.error(JWT_TOKEN_INVALID, ex);
			throw new BadCredentialsException(JWT_TOKEN_INVALID, ex);
		} catch (ExpiredJwtException expiredEx) {
			logger.info(JWT_TOKEN_EXPIRED, expiredEx);
			throw new JwtTokenExpiredException(this, JWT_TOKEN_EXPIRED, expiredEx);
		}
	}

}
