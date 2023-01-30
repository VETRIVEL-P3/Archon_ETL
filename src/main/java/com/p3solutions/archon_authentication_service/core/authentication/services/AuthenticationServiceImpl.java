package com.p3solutions.archon_authentication_service.core.authentication.services;

import com.p3solutions.archon_authentication_service.core.authentication.enums.AuthType;
import com.p3solutions.archon_authentication_service.core.user.services.UserService;
import com.p3solutions.common_beans_dto.global_groups_roles.abstract_repository.GlobalGroupAbstractRepository;
import com.p3solutions.common_beans_dto.global_groups_roles.mapper_beans.GlobalGroupMapperBean;
import com.p3solutions.common_beans_dto.users.abstract_repository.InviteUserAbstractRepository;
import com.p3solutions.common_beans_dto.users.abstract_repository.UserAbstractRepository;
import com.p3solutions.common_beans_dto.users.mapper_beans.InviteUserMapperBean;
import com.p3solutions.common_beans_dto.users.mapper_beans.UserModelMapperBean;
import com.p3solutions.utility.common_exceptions.BadRequestException;
import com.p3solutions.utility.internationalization.Translator;
import com.p3solutions.utility.mapper.MapperUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

@Service
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {

    @Autowired
    private InviteUserAbstractRepository inviteUserAbstractRepository;
   /* @Autowired
    private GlobalGroupRepository globalGroupRepository;*/
   @Autowired
   private GlobalGroupAbstractRepository globalGroupAbstractRepository;
    @Autowired
    private UserAbstractRepository userAbstractRepository;
    @Autowired
    private Translator translator;
    @Autowired
    private UserService userService;
    @Autowired
    private MapperUtils mapperUtils;

    @Value("${saml.enabled:false}")
    private Boolean samlEnabled;

    @Value("${enableldapauth:false}")
    private Boolean ldapEnabled;

    //private static final Logger LOGGER = Loggers.getLogger("AuthenticationServiceImpl");

    @Override
    public UserModelMapperBean signUpUser(UserModelMapperBean userModelResponseDTO) throws BadRequestException {
        Optional<InviteUserMapperBean> inviteUserModelOpt = inviteUserAbstractRepository.findByEmailAddress(userModelResponseDTO.getEmailAddress());
        InviteUserMapperBean inviteUserModel = inviteUserModelOpt.get();
        if(!userService.isValidEmailAddress(inviteUserModel.getEmailAddress())){
            throw new BadRequestException(Translator.toLocale("user.inValidEmail"));
        }
		userModelResponseDTO.setGlobalGroups(inviteUserModel.getGlobalGroups());
		userModelResponseDTO.setBusinessJustification(inviteUserModel.getBusinessJustification());
        // updating the number of users assigned to this group
        for (GlobalGroupMapperBean groupModel : inviteUserModel.getGlobalGroups()) {
            Optional<GlobalGroupMapperBean> globalGroupModelOpt = globalGroupAbstractRepository
                    .findByGroupName(groupModel.getGroupName());

            GlobalGroupMapperBean globalGroupResponseDTO = globalGroupModelOpt.get();
            if (globalGroupResponseDTO.getAssignedUsersCount() != null) {
                globalGroupResponseDTO.setAssignedUsersCount(globalGroupResponseDTO.getAssignedUsersCount() + 1);
                // globalGroupModel.setUserPercentage(addPercentage(globalGroupModel));

            }
            globalGroupAbstractRepository.save(globalGroupResponseDTO);
        }
		userModelResponseDTO.setGlobalRoles(userService.getRolesInGroup(userModelResponseDTO.getGlobalGroups()));
        UserModelMapperBean model = userAbstractRepository.save(userModelResponseDTO);
        inviteUserAbstractRepository.delete(inviteUserModel);
        return model;
    }

    /**
     * user creation service (sign up) which will be triggered automatically by SAML and specific for SAML users
     * @param userModelResponseDTO
     * @param groups
     * @return
     */
    @Override
    public UserModelMapperBean signUpSAMLUser(UserModelMapperBean userModelResponseDTO, List<GlobalGroupMapperBean> groups) throws BadRequestException {
        if (groups.isEmpty()) {
            log.error(translator.toLocale("saml.no.rules"));
            throw new BadRequestException(translator.toLocale("saml.no.rules"));
        }
        String businessJustification = "User created by SAML-SSO";
        userModelResponseDTO.setGlobalGroups(groups);
        userModelResponseDTO.setBusinessJustification(businessJustification);
        // updating the number of users assigned to this group
        for (GlobalGroupMapperBean groupModel : groups) {
            Optional<GlobalGroupMapperBean> globalGroupModelOpt = globalGroupAbstractRepository
                    .findByGroupName(groupModel.getGroupName());

            GlobalGroupMapperBean globalGroupResponseDTO = globalGroupModelOpt.get();
            if (globalGroupResponseDTO.getAssignedUsersCount() != null) {
                globalGroupResponseDTO.setAssignedUsersCount(globalGroupResponseDTO.getAssignedUsersCount() + 1);
                // globalGroupModel.setUserPercentage(addPercentage(globalGroupModel));
            }
            globalGroupAbstractRepository.save(globalGroupResponseDTO);
        }
        userModelResponseDTO.setGlobalRoles(userService.getRolesInGroup(userModelResponseDTO.getGlobalGroups()));
        UserModelMapperBean model = userAbstractRepository.save(userModelResponseDTO);
//        UserModelMapperBean model = mapperUtils.map(userModelResponseDTO, UserModelMapperBean.class);
        return model;
    }

    @Override
    public void userIdFirstCharValidation(String userId) throws BadRequestException {
        String userIdRegex = "^[a-zA-Z][a-zA-Z0-9_]*$";
        Pattern pat = Pattern.compile(userIdRegex);
        if (!Pattern.matches(userIdRegex, userId)) {
            throw new BadRequestException(translator.toLocale("user.userIdConstraints"));
                    //messageSource.getMessage("user.userIdConstraints", new String[0], LocaleContextHolder.getLocale()));
        }

    }

    @Override
    public void userIdMaxCharValidation(String userId) throws BadRequestException {
        if (userId.length() < 5) {
            throw new BadRequestException(translator.toLocale("user.userIdLengthmin"));
//                    messageSource.getMessage("user.userIdLengthmin", new String[0], LocaleContextHolder.getLocale()));
        }
        if (userId.length() > 15) {
            throw new BadRequestException(translator.toLocale("user.userIdLengthmax"));
            		//messageSource.getMessage("user.userIdLengthmax", new String[0], LocaleContextHolder.getLocale()));
        }

    }

    @Override
    public AuthType getActiveAuth() {
        if (samlEnabled)
            return AuthType.SAML_SSO;
        else if (ldapEnabled)
            return AuthType.LDAP;
        else
            return AuthType.DATABASE;
    }

}
