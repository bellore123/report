package com.cybershield.service;

import com.cybershield.dto.LoginRequest;
import com.cybershield.dto.LoginResponse;
import com.cybershield.model.User;
import com.cybershield.repository.AuditLogRepository;
import com.cybershield.repository.UserRepository;
import com.cybershield.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

/**
 * AuthService — handles user authentication and login business logic.
 *
 * Key responsibilities:
 *   1. Validate credentials (username + BCrypt password match)
 *   2. Check account lockout status (brute-force protection — patched version)
 *   3. Count recent failed logins and lock account when threshold exceeded
 *   4. Write LOGIN_OK or LOGIN_FAIL to AuditLog
 *   5. Generate and return JWT on successful login
 *
 * Attack 1 (Brute Force) is demonstrated here:
 *   VULNERABLE version: no lockout check — every attempt goes through
 *   PATCHED version:    account locks after 5 failures in 2 minutes
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final AuditLogService auditLogService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final IncidentService incidentService;

    // Brute-force protection thresholds
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCKOUT_WINDOW_MINUTES = 2;
    private static final int LOCKOUT_DURATION_MINUTES = 15;

    /**
     * Authenticate a user and return a JWT.
     *
     * @param request   Login credentials from the request body
     * @param ipAddress Client IP address (for audit log + brute-force tracking)
     * @return LoginResponse with JWT if successful
     * @throws RuntimeException if credentials are invalid or account is locked
     */
    public LoginResponse login(LoginRequest request, String ipAddress) {

        // Step 1: Find the user by username
        User user = userRepository.findByUsername(request.getUsername()).orElse(null);

        if (user == null) {
            // User does not exist — log the failed attempt and reject
            auditLogService.logLogin(null, request.getUsername(), ipAddress, false);
            throw new RuntimeException("Invalid username or password");
        }

        // Step 2: Check if account is currently locked (patched version)
        // VULNERABLE version: comment out this entire block
        if (user.getLockedUntil() != null &&
                user.getLockedUntil().isAfter(LocalDateTime.now())) {
            long minutesLeft = java.time.Duration.between(
                    LocalDateTime.now(), user.getLockedUntil()).toMinutes();
            log.warn("Login blocked — account '{}' is locked for {} more minutes",
                    user.getUsername(), minutesLeft);
            auditLogService.logLogin(user.getId(), request.getUsername(), ipAddress, false);
            incidentService.triggerUserRiskCheck(request.getUsername(), ipAddress);
            throw new RuntimeException(
                "Account locked due to too many failed attempts. Try again in "
                + minutesLeft + " minutes.");
        }

        // Step 3: Validate password with BCrypt
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            // Wrong password — log the failure and check if we should lock the account
            auditLogService.logLogin(user.getId(), request.getUsername(), ipAddress, false);

            // Count recent failures (patched version — remove for vulnerable demo)
            long recentFailures = auditLogRepository.countFailedLoginsSince(
                    request.getUsername(),
                    LocalDateTime.now().minusMinutes(LOCKOUT_WINDOW_MINUTES)
            );

            log.warn("Failed login attempt #{} for user '{}' from IP {}",
                    recentFailures, request.getUsername(), ipAddress);

            user.setFailedLoginAttempts((int) recentFailures);

            // Lock account if threshold exceeded (patched version)
            if (recentFailures >= MAX_FAILED_ATTEMPTS) {
                user.setLockedUntil(
                    LocalDateTime.now().plusMinutes(LOCKOUT_DURATION_MINUTES)
                );
                log.warn("Account '{}' LOCKED for {} minutes after {} failed attempts",
                        user.getUsername(), LOCKOUT_DURATION_MINUTES, recentFailures);
            }
            userRepository.save(user);

            // PHASE 3: Trigger Risk Engine after every failed login
            // This may auto-create a security incident if score >= 50
            incidentService.triggerUserRiskCheck(request.getUsername(), ipAddress);

            throw new RuntimeException("Invalid username or password");
        }

        // Step 4: Login successful — reset lockout state
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        // Step 5: Log the successful login
        auditLogService.logLogin(user.getId(), request.getUsername(), ipAddress, true);

        // Step 6: Generate JWT with username and role
        String token = jwtUtil.generateToken(
                user.getUsername(),
                user.getRole().name()
        );

        log.info("User '{}' logged in successfully with role '{}'",
                user.getUsername(), user.getRole());

        return LoginResponse.builder()
                .token(token)
                .username(user.getUsername())
                .role(user.getRole().name())
                .message("Login successful")
                .build();
    }
}
