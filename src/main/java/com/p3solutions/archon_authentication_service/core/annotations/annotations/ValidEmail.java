/**
 * 
 */
package com.p3solutions.archon_authentication_service.core.annotations.annotations;

import com.p3solutions.archon_authentication_service.core.annotations.classes.EmailValidator;
import com.p3solutions.archon_authentication_service.core.constants.ValidationConstants;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.*;

/**
 * Validates if the Email is Valid
 * 
 * @author saideepak
 *
 */
@Target(value = { ElementType.TYPE, ElementType.FIELD, ElementType.ANNOTATION_TYPE })
@Retention(value = RetentionPolicy.RUNTIME)
@Constraint(validatedBy = EmailValidator.class)
@Documented
public @interface ValidEmail {
	String message() default ValidationConstants.INVALID_EMAIL;

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};
}
