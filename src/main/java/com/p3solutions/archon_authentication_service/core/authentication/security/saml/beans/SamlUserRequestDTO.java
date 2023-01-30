package com.p3solutions.archon_authentication_service.core.authentication.security.saml.beans;

import lombok.*;

import java.util.List;

@Data
@AllArgsConstructor(access = AccessLevel.PUBLIC)
@Builder
@NoArgsConstructor(access = AccessLevel.PUBLIC)
public class SamlUserRequestDTO {
    private String userName;
    private String firstName;
    private String lastName;
    private String emailAddress;
    private List<String> groupList;
}
