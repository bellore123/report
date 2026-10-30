package com.cybershield.dto;

import com.cybershield.model.User;
import lombok.Data;

/**
 * UserRequest — NEW MODULE (PS point 9: User Access & Identity
 * Management — "administrators can define user roles, permissions,
 * and access levels").
 *
 * Used for both creating a new user (password required) and updating
 * an existing one (password optional — omit to leave unchanged).
 */
@Data
public class UserRequest {
    private String username;
    private String email;
    private String password;       // plain text, only ever used to hash — never stored/returned as-is
    private User.Role role;
    private String department;
    private Boolean isActive;
}
