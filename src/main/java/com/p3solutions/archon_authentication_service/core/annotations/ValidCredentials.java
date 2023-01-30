package com.p3solutions.archon_authentication_service.core.annotations;

import com.p3solutions.archon_authentication_service.core.annotations.classes.CredentialsValidator;
import com.p3solutions.archon_authentication_service.core.constants.ValidationConstants;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.*;

@Target(value = { ElementType.TYPE, ElementType.FIELD, ElementType.ANNOTATION_TYPE })
@Retention(value = RetentionPolicy.RUNTIME)
@Constraint(validatedBy = CredentialsValidator.class)
@Documented
public @interface ValidCredentials {
	
	String message() default ValidationConstants.INVALID_CREDENTIALS;

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};

}
