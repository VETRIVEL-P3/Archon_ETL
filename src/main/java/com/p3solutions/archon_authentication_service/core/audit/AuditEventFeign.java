package com.p3solutions.archon_authentication_service.core.audit;

import com.p3solutions.common_beans_dto.audit.dto.request.AuditRequestDTO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient("https://audit-service")
public interface AuditEventFeign {
	@PostMapping("/audits/eventSave")
	public String auditEventDetailToSave(@RequestBody AuditRequestDTO auditInput, @RequestHeader("Authorization") String token);

}
