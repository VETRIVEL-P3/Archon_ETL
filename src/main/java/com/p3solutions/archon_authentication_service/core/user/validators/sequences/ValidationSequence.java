package com.p3solutions.archon_authentication_service.core.user.validators.sequences;

import javax.validation.GroupSequence;
import javax.validation.groups.Default;

import com.p3solutions.archon_authentication_service.core.user.validators.ExistenceGroup;
import com.p3solutions.archon_authentication_service.core.user.validators.PreExistenceGroup;
import com.p3solutions.archon_authentication_service.core.user.validators.ValidityGroup;

@GroupSequence({ Default.class, ValidityGroup.class,PreExistenceGroup.class,ExistenceGroup.class })
public interface ValidationSequence {

}
