package com.cybershield.controller;

import com.cybershield.dto.UserRequest;
import com.cybershield.model.User;
import com.cybershield.repository.UserRepository;
import com.cybershield.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * UserController — NEW MODULE (PS point 9: User Access & Identity
 * Management).
 *
 * ADMIN-only for every operation — user/role management is exactly the
 * kind of privileged action that shouldn't be reachable by
 * SERVER_ADMIN or VIEWER accounts.
 *
 * Note: User.passwordHash is annotated @JsonIgnore on the entity, so
 * it is never present in any of these responses.
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final UserRepository userRepository;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<User>> getAll() {
        return ResponseEntity.ok(userService.getAll());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getById(@PathVariable Long id) {
        try {
            return ResponseEntity.ok(userService.getById(id));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> create(@RequestBody UserRequest req,
                                     @AuthenticationPrincipal UserDetails userDetails,
                                     HttpServletRequest request) {
        try {
            User created = userService.create(req, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> update(@PathVariable Long id,
                                     @RequestBody UserRequest req,
                                     @AuthenticationPrincipal UserDetails userDetails,
                                     HttpServletRequest request) {
        try {
            User updated = userService.update(id, req, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.ok(updated);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> delete(@PathVariable Long id,
                                     @AuthenticationPrincipal UserDetails userDetails,
                                     HttpServletRequest request) {
        try {
            userService.delete(id, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    private Long getUserId(UserDetails u) {
        return userRepository.findByUsername(u.getUsername()).map(User::getId).orElse(null);
    }

    private String getClientIp(HttpServletRequest r) {
        String xff = r.getHeader("X-Forwarded-For");
        return (xff != null && !xff.isEmpty()) ? xff.split(",")[0].trim() : r.getRemoteAddr();
    }
}
