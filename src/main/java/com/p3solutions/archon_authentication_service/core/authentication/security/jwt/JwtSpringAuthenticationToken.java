package com.p3solutions.archon_authentication_service.core.authentication.security.jwt;

import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.JwtTokenGenerator.UserInfo;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans.JwtToken;
import com.p3solutions.common_beans_dto.authentication.beans.AuthUserDetails;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@EqualsAndHashCode(callSuper = true)
@Getter
public class JwtSpringAuthenticationToken extends AbstractAuthenticationToken {
  private static final long serialVersionUID = 2877954820905567501L;

  private JwtToken accessToken;
  private AuthUserDetails userAuthenticationData;
  private UserInfo userInfo;

  public JwtSpringAuthenticationToken(JwtToken unsafeToken) {
    super(null);
    this.accessToken = unsafeToken;
    this.setAuthenticated(false);
  }

  public JwtSpringAuthenticationToken(
          AuthUserDetails userAuthenticationData, Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    this.eraseCredentials();
    this.userAuthenticationData = userAuthenticationData;
    super.setAuthenticated(true);
  }

  @Override
  public void setAuthenticated(boolean authenticated) {
    if (authenticated) {
      throw new IllegalArgumentException(
          "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
    }
    super.setAuthenticated(false);
  }

  @Override
  public Object getCredentials() {
    return accessToken;
  }

  @Override
  public Object getPrincipal() {
    return this.userAuthenticationData;
  }

  @Override
  public void eraseCredentials() {
    super.eraseCredentials();
    this.accessToken = null;
  }
}
