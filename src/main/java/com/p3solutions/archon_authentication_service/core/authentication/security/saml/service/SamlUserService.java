package com.p3solutions.archon_authentication_service.core.authentication.security.saml.service;

import com.p3solutions.archon_authentication_service.core.authentication.security.ajax.AjaxAuthenticationProvider;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.JwtTokenGenerator;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans.JwtToken;
import com.p3solutions.archon_authentication_service.core.user.services.UserService;
import com.p3solutions.common_beans_dto.authentication.beans.AuthUserDetails;
import com.p3solutions.common_beans_dto.users.abstract_repository.UserAbstractRepository;
import com.p3solutions.archon_authentication_service.core.authentication.security.saml.beans.SamlUserRequestDTO;
import com.p3solutions.common_beans_dto.users.dto.request.UserCreateDTO;
import com.p3solutions.common_beans_dto.users.mapper_beans.UserModelMapperBean;
import com.p3solutions.utility.common_exceptions.BadRequestException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for the user creation and validation, token generation for saml service
 * @author seelan
 */
@Service
public class SamlUserService {

    @Autowired
    UserAbstractRepository userAbstractRepository;

    @Autowired
    private AjaxAuthenticationProvider authenticationManager;

    @Autowired
    private JwtTokenGenerator tokenFactory;

    @Autowired
    private UserService userService;

    @Autowired
    @Qualifier("roleMapper")
    private Map<String, String> roleMap;

    public String generateToken (UserModelMapperBean user, String tokenType) {
        final Authentication authentication = authenticationManager
                .anonymousUserAuthenticate(user);
        AuthUserDetails userContext = (AuthUserDetails) authentication.getPrincipal();
        if (tokenType.equals("accessToken")) {
            JwtToken jwtToken = tokenFactory.generateAccessJwtTokenForConfig(userContext, false);
            return jwtToken.getToken();
        } else {
            JwtToken jwtToken = tokenFactory.generateRefreshToken(userContext);
            return jwtToken.getToken();
        }
    }

    public UserModelMapperBean createSAMLUserEntry (User user) throws BadRequestException {
        UserCreateDTO userCreateDTO = constructUserCreateDTO(user);
        List<String> groupNames = extractGroupNames(user);
        return userService.createSAMLUser(userCreateDTO, groupNames);
    }
    public UserModelMapperBean createSAMLUserEntry (SamlUserRequestDTO samlUserRequestDTO) throws BadRequestException {
        UserCreateDTO dto = new UserCreateDTO();
        dto.setEmailAddress(samlUserRequestDTO.getEmailAddress());
        dto.setFirstName(samlUserRequestDTO.getFirstName());
        dto.setLastName(samlUserRequestDTO.getLastName());
        dto.setUserId(samlUserRequestDTO.getUserName());
        List<String> groupNames = samlUserRequestDTO.getGroupList();
        return userService.createSAMLUser(dto, groupNames);
    }

    private List<String> extractGroupNames(User user) {
        List<String> groups = new ArrayList<>();
        List<GrantedAuthority> authorities = user.getAuthorities().stream().collect(Collectors.toList());
        for (GrantedAuthority authority : authorities) {
//            if (authority.getAuthority().startsWith("ARCHON")
//                || authority.getAuthority().startsWith("ROLE") || authority.getAuthority().startsWith("GROUP")) {
//                groups.add(authority.getAuthority());
//            }
            if (roleMap.containsKey(authority.getAuthority())) {
                String dedicatedGroup = roleMap.get(authority.getAuthority());
                groups.add(dedicatedGroup);
            } else {
                groups.add(authority.getAuthority());
            }
        }
        return groups;
    }

    private UserCreateDTO constructUserCreateDTO(User user) {
        List<GrantedAuthority> authorities = user.getAuthorities().stream().collect(Collectors.toList());
        String firstname = "";
        String lastname = "";
        String email = "";
        for (GrantedAuthority grantedAuthority : authorities) {
            if (grantedAuthority.getAuthority().startsWith("firstName:"))
                firstname = grantedAuthority.getAuthority().replace("firstName:", "");
            else if (grantedAuthority.getAuthority().startsWith("lastName:"))
                lastname = grantedAuthority.getAuthority().replace("lastName:", "");
            else if (grantedAuthority.getAuthority().startsWith("email"))
                email = grantedAuthority.getAuthority().replace("email:", "");
        }

        UserCreateDTO dto = new UserCreateDTO();
        dto.setEmailAddress(email);
        dto.setFirstName(firstname);
        dto.setLastName(lastname);
        dto.setUserId(user.getUsername());

        return dto;
    }

    /**
     * validate whether the previous assigned groups are modified/removed
     */
    public UserModelMapperBean updateUserRoles(User user, UserModelMapperBean userBean) throws BadRequestException {
        List<String> newGroups = extractGroupNames(user);
        return userService.updateSAMLUser(userBean, newGroups);
    }
    /**
     * validate whether the previous assigned groups are modified/removed
     */
    public UserModelMapperBean updateUserRoles(SamlUserRequestDTO samlUserRequestDTO, UserModelMapperBean userBean) throws BadRequestException {
        List<String> newGroups = samlUserRequestDTO.getGroupList();
        return userService.updateSAMLUser(userBean, newGroups);
    }
}
