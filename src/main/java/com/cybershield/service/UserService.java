package com.cybershield.service;

import com.cybershield.dto.UserRequest;
import com.cybershield.model.AuditLog.Action;
import com.cybershield.model.AuditLog.TargetType;
import com.cybershield.model.User;
import com.cybershield.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * UserService — NEW MODULE (PS point 9: User Access & Identity
 * Management).
 *
 * Previously, user accounts could only be created via the DB seed
 * script — there was no admin-manageable way to add a user, change
 * their role, or deactivate them. This gives ADMIN users exactly that,
 * with every action written to the audit log like the rest of the app.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditLogService auditLogService;

    public List<User> getAll() {
        return userRepository.findAll();
    }

    public User getById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + id));
    }

    public User create(UserRequest req, Long actorUserId, String ip) {
        if (req.getUsername() == null || req.getUsername().isBlank()) {
            throw new RuntimeException("Username is required");
        }
        if (req.getPassword() == null || req.getPassword().length() < 6) {
            throw new RuntimeException("Password must be at least 6 characters");
        }
        if (userRepository.existsByUsername(req.getUsername())) {
            throw new RuntimeException("Username already taken");
        }
        if (req.getEmail() != null && userRepository.existsByEmail(req.getEmail())) {
            throw new RuntimeException("Email already in use");
        }

        User user = User.builder()
                .username(req.getUsername())
                .email(req.getEmail())
                .passwordHash(passwordEncoder.encode(req.getPassword()))
                .role(req.getRole() != null ? req.getRole() : User.Role.VIEWER)
                .department(req.getDepartment())
                .isActive(req.getIsActive() == null || req.getIsActive())
                .failedLoginAttempts(0)
                .build();

        User saved = userRepository.save(user);
        auditLogService.log(actorUserId, Action.CREATE, TargetType.USER, saved.getId(), ip,
                "Created user '" + saved.getUsername() + "' with role " + saved.getRole());
        return saved;
    }

    public User update(Long id, UserRequest req, Long actorUserId, String ip) {
        User existing = getById(id);

        if (req.getEmail() != null && !req.getEmail().equals(existing.getEmail())
                && userRepository.existsByEmail(req.getEmail())) {
            throw new RuntimeException("Email already in use");
        }

        if (req.getEmail() != null) existing.setEmail(req.getEmail());
        if (req.getRole() != null) existing.setRole(req.getRole());
        if (req.getDepartment() != null) existing.setDepartment(req.getDepartment());
        if (req.getIsActive() != null) existing.setActive(req.getIsActive());

        // Password change is optional — only re-hash if a new one was provided
        if (req.getPassword() != null && !req.getPassword().isBlank()) {
            if (req.getPassword().length() < 6) {
                throw new RuntimeException("Password must be at least 6 characters");
            }
            existing.setPasswordHash(passwordEncoder.encode(req.getPassword()));
        }

        User saved = userRepository.save(existing);
        auditLogService.log(actorUserId, Action.UPDATE, TargetType.USER, id, ip,
                "Updated user '" + saved.getUsername() + "' (role=" + saved.getRole() +
                        ", active=" + saved.isActive() + ")");
        return saved;
    }

    public void delete(Long id, Long actorUserId, String ip) {
        User user = getById(id);
        if (user.getId().equals(actorUserId)) {
            throw new RuntimeException("You cannot delete your own account");
        }
        userRepository.deleteById(id);
        auditLogService.log(actorUserId, Action.DELETE, TargetType.USER, id, ip,
                "Deleted user '" + user.getUsername() + "'");
    }
}
