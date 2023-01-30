package com.p3solutions.archon_authentication_service.core.authentication.security.ajax;

import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;



@Data
public class LoginRequest {
	
	@NotEmpty(message = "field.notempty")
	private String userId;
	@NotEmpty(message = "field.notempty")
	private String password;

	@JsonCreator
	public LoginRequest(@JsonProperty("userId") String userId, @JsonProperty("password") String password) {
		
		this.userId = userId;
		this.password = password;
	}

	
}
