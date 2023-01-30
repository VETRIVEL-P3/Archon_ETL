/**
 * 
 */
package com.p3solutions.archon_authentication_service.core.user.validators.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.validation.Constraint;
import javax.validation.Payload;

import com.p3solutions.archon_authentication_service.core.constants.ValidationConstants;
import com.p3solutions.archon_authentication_service.core.user.validators.CredentialsMatchesValidator;

/**
 * @author saideepak
 *
 */
@Target(value = { ElementType.TYPE, ElementType.ANNOTATION_TYPE })
@Retention(value = RetentionPolicy.RUNTIME)
@Constraint(validatedBy = CredentialsMatchesValidator.class)
@Documented
public @interface CredentialsMatches {
	String message() default ValidationConstants.CREDENTIALS_DONT_MATCH;

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};
}
