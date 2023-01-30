package com.p3solutions.archon_authentication_service.core.authentication.security.saml.stereotypes;

import java.lang.annotation.*;

@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CurrentUser {}
