
package com.p3solutions.archon_authentication_service.core.authentication.security.saml.config;

import com.p3solutions.archon_authentication_service.core.license_management.LicenseCheckerService;
import com.p3solutions.utility.common_exceptions.LicenseExpiredException;
import com.p3solutions.utility.internationalization.Translator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
@Slf4j
public class LicenseHandlerInterceptor implements HandlerInterceptor {

  @Autowired
  private LicenseCheckerService licenseCheckerService;
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws LicenseExpiredException {

        log.info("~~~ Pre-Handle");
        boolean validationCheck=true;
/* If license expired we cannot generate token,hence it is not required */
//       boolean validationCheck=licenseCheckerService.archonLicenseCheck();
//       if(!validationCheck){
//            throw new LicenseExpiredException(Translator.toLocale("license.expired"));
//       }
        return validationCheck;
    }
}
