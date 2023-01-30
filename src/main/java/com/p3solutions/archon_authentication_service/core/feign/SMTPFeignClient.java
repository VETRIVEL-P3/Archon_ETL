package com.p3solutions.archon_authentication_service.core.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;

@FeignClient("https://archon-user-service")
public interface SMTPFeignClient {

	@GetMapping("v1/user-service/api/system-management/SMTPModel")
	public Map<String,String> fetchSMTPModel();
}
