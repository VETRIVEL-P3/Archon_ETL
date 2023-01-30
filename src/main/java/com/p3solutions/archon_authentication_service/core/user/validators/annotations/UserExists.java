package com.p3solutions.archon_authentication_service.core.user.validators.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.validation.Constraint;
import javax.validation.Payload;

import com.p3solutions.archon_authentication_service.core.user.validators.UserValidator;

@Target(value = { ElementType.TYPE, ElementType.FIELD, ElementType.ANNOTATION_TYPE })
@Retention(value = RetentionPolicy.RUNTIME)
@Constraint(validatedBy = UserValidator.class)
@Documented
public @interface UserExists {
	String message() default "Email Address you have provided is already registered";

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};
}
