package com.p3solutions.archon_authentication_service.core.authentication.security.ajax.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.JwtTokenGenerator;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans.JwtToken;
import com.p3solutions.archon_authentication_service.core.constants.JwtConstants;
import com.p3solutions.common_beans_dto.authentication.beans.AuthUserDetails;
import com.p3solutions.common_beans_dto.common_beans.ApplicationResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class AjaxSuccessHandler implements AuthenticationSuccessHandler {
  private final ObjectMapper mapper;
  private final JwtTokenGenerator jwtTokenGenerator;

  @Autowired
  public AjaxSuccessHandler(final ObjectMapper mapper, final JwtTokenGenerator jwtTokenGenerator) {
    this.mapper = mapper;
    this.jwtTokenGenerator = jwtTokenGenerator;
  }

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException {

    AuthUserDetails userContext = (AuthUserDetails) authentication.getPrincipal();

    JwtToken accessToken = jwtTokenGenerator.generateAccessJwtToken(userContext);
    JwtToken refreshToken = jwtTokenGenerator.generateRefreshToken(userContext);

    Map<String, String> tokenMap = new HashMap<>();
    tokenMap.put(JwtConstants.ApiResponseFields.ACCESS_TOKEN, accessToken.getToken());
    tokenMap.put(JwtConstants.ApiResponseFields.REFRESH_TOKEN, refreshToken.getToken());

    response.setStatus(HttpStatus.OK.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    mapper.writeValue(response.getWriter(), ApplicationResponse.success(tokenMap));

    clearAuthenticationAttributes(request);
  }

  /**
   * Removes temporary authentication-related data which may have been stored in the session during
   * the authentication process..
   */
  private void clearAuthenticationAttributes(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    if (session != null) {
      session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }
  }
}
