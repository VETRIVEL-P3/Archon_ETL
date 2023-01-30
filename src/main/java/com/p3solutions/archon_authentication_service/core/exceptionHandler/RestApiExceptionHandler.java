package com.p3solutions.archon_authentication_service.core.exceptionHandler;

import com.p3solutions.common_beans_dto.common_beans.ApiFailureMessages;
import com.p3solutions.common_beans_dto.common_beans.ApplicationResponseFailure;
import com.p3solutions.common_beans_dto.common_constants.FailureMessages;
import com.p3solutions.utility.common_exceptions.InvalidInput;
import com.p3solutions.utility.internationalization.Translator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;

/**
 * REST API Exception Handler handles all the global level exceptions occurred
 * in the Controller layer
 *
 * @author vishwabhat
 */
@ControllerAdvice
public class RestApiExceptionHandler extends ResponseEntityExceptionHandler {

	private Logger LOGGER = LoggerFactory.getLogger(getClass());

//	@Autowired
//	private MessageSource messageSource;

	/**
	 * This method handles if the request body/parameter is not processable
	 */
	@Override
	protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
			HttpHeaders headers, HttpStatus status, WebRequest request) {
		return new ResponseEntity<>(ApplicationResponseFailure.failure(FailureMessages.INVALID_REQUEST_CONTENT),
				UNPROCESSABLE_ENTITY);
	}

	/**
	 * This method handles any {@link RuntimeException} that occurs in the System
	 */
	@ExceptionHandler(value = { RuntimeException.class })
	protected ResponseEntity<Object> handleConflict(RuntimeException ex, WebRequest request) {
		/*commented logs because :"untrusted data into a log file allows an attacker to forge log": veracode */
		//LOGGER.error("Handling conflict \n Request: {} \n Exception: {}", request, ex);
		final ApplicationResponseFailure responseBody = ApplicationResponseFailure.failure(ex.getMessage());
		return handleExceptionInternal(ex, responseBody, new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR, request);
	}

	@ExceptionHandler(value = { InvalidInput.class })
	protected ResponseEntity<Object> handleConflict(InvalidInput ex, WebRequest request) {
		/*commented logs because :"untrusted data into a log file allows an attacker to forge log": veracode */
		//LOGGER.error("Handling conflict \n Request: {} \n Exception: {}", request, ex);
		final ApplicationResponseFailure responseBody = ApplicationResponseFailure.failureInput(ex.getMessage());
		return handleExceptionInternal(ex, responseBody, new HttpHeaders(), HttpStatus.BAD_REQUEST, request);
	}

	/**
	 * This method handles any {@link AccessDeniedException} that occurs in the
	 * System
	 *
	 */
	@ExceptionHandler(value = { AccessDeniedException.class })
	protected ResponseEntity<Object> handleDeniedAccess(AccessDeniedException ex, WebRequest request) {
		/*commented logs because :"untrusted data into a log file allows an attacker to forge log": veracode */
		//LOGGER.error("Handling conflict \n Request: {} \n Exception: {}", request, ex);
		final ApplicationResponseFailure responseBody =  ApplicationResponseFailure.failure(ex.getMessage());
		return handleExceptionInternal(ex, responseBody, new HttpHeaders(), HttpStatus.FORBIDDEN, request);
	}

	/**
	 * This method handles exceptions when there are form errors
	 */
	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
			HttpHeaders headers, HttpStatus status, WebRequest request) {

		BindingResult bindingResult = ex.getBindingResult();

		List<String> errors = new ArrayList<>();
		List<FieldError> fieldErrors = bindingResult.getFieldErrors();
		List<ObjectError> globalErrors = bindingResult.getGlobalErrors();

		for (FieldError error : fieldErrors) {
			errors.add(Translator.toLocale(error.getDefaultMessage(), new String[] { error.getField() }));
					//messageSource.getMessage(error.getDefaultMessage(), new String[] { error.getField() }, Locale.US));
		}

		for (ObjectError error : globalErrors) {
			errors.add(Translator.toLocale(error.getDefaultMessage()));
					//messageSource.getMessage(error.getDefaultMessage(), new Object[] {}, Locale.US));
		}
//
//		List<ApiFieldError> apiFieldErrors = reverseList(
//				bindingResult.getFieldErrors().stream().map(fieldError -> new ApiFieldError(fieldError.getField(),
////								fieldError.getCode(), new Object[] {}, Locale.US
//						messageSource.getMessage(fieldError.getDefaultMessage(), new String[] { fieldError.getField() },
//								Locale.US),
//						fieldError.getRejectedValue())).collect(toList()));
//		List<ApiGlobalError> apiGlobalErrors = reverseList(bindingResult.getGlobalErrors().stream()
//				.map(globalError -> new ApiGlobalError(
//						messageSource.getMessage(globalError.getCode(), new Object[] {}, Locale.US)))
//				.collect(toList()));

		String errorMessage;

//		if (!apiFieldErrors.isEmpty()) {
//			errorMessage = apiFieldErrors.get(0).getCode();
//
//		} else if (!apiGlobalErrors.isEmpty()) {
//			errorMessage = apiGlobalErrors.get(0).getCode();
//		} else

		if (!errors.isEmpty()) {
			errorMessage = errors.get(0);
		} else {
			errorMessage = ApiFailureMessages.TECHNICAL_ERROR;
		}

//		ApiErrorsView apiErrorsView = new ApiErrorsView(apiFieldErrors, apiGlobalErrors);
//		log.error("Invalid method argument: {}", apiErrorsView);

		return new ResponseEntity<>(ApplicationResponseFailure.failure(errorMessage, errors), HttpStatus.INTERNAL_SERVER_ERROR);

	}

//	Reverse List
	public static <T> List<T> reverseList(List<T> list) {
		return IntStream.range(0, list.size()).mapToObj(i -> list.get(list.size() - 1 - i))
				.collect(Collectors.toCollection(ArrayList::new));
	}
}
