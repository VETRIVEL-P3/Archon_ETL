package com.p3solutions.archon_authentication_service.core.permissions;

/**
 * Represents base role permission for any role
 *
 * @author vishwabhat
 */
public interface ApplicationRole {
  /**
   * ID of the role
   */
  String roleId();

  /**
   * Name of the role
   */
  String roleName();

  /**
   * Type of the role
   *
   * @see RoleType
   */
  RoleType type();
}
