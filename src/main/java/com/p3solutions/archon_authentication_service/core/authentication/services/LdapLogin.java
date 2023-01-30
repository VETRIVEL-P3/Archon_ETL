package com.p3solutions.archon_authentication_service.core.authentication.services;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

import java.util.Map;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient("https://ldap-authentication")
public interface LdapLogin {
    @PostMapping(value = "/login",consumes = APPLICATION_FORM_URLENCODED_VALUE)
    String loginDetails(@RequestBody Map<String, ?> form);
}

