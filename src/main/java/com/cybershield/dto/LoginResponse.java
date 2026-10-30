package com.cybershield.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * LoginResponse — what the server returns after a successful login.
 *
 * Example JSON returned:
 * {
 *   "token": "eyJhbGciOiJIUzI1NiJ9...",
 *   "username": "santhosh",
 *   "role": "ADMIN",
 *   "message": "Login successful"
 * }
 *
 * The client stores this token and sends it in every subsequent request:
 * Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {

    private String token;        // JWT token — store this in localStorage
    private String username;
    private String role;
    private String message;
}
