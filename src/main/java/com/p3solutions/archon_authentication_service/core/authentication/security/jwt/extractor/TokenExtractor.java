package com.p3solutions.archon_authentication_service.core.authentication.security.jwt.extractor;

import javax.servlet.http.HttpServletRequest;

public interface TokenExtractor {
  String extract(HttpServletRequest request);
}
