package com.cybershield.controller;

import com.cybershield.model.Firewall;
import com.cybershield.repository.UserRepository;
import com.cybershield.service.FirewallService;
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
 * FirewallController — REST API for Firewall management.
 *
 * RBAC:
 *   GET    → ADMIN, SERVER_ADMIN, VIEWER
 *   POST/PUT → ADMIN, SERVER_ADMIN
 *   DELETE → ADMIN only
 */
@RestController
@RequestMapping("/api/firewalls")
@RequiredArgsConstructor
public class FirewallController {

    private final FirewallService firewallService;
    private final UserRepository userRepository;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<Firewall>> getAll() {
        return ResponseEntity.ok(firewallService.getAll());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<?> getById(@PathVariable Long id) {
        try {
            return ResponseEntity.ok(firewallService.getById(id));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> create(@RequestBody Firewall firewall,
                                    @AuthenticationPrincipal UserDetails userDetails,
                                    HttpServletRequest request) {
        try {
            Long userId = getUserId(userDetails);
            Firewall created = firewallService.create(firewall, userId, getClientIp(request));
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> update(@PathVariable Long id,
                                    @RequestBody Firewall firewall,
                                    @AuthenticationPrincipal UserDetails userDetails,
                                    HttpServletRequest request) {
        try {
            Firewall updated = firewallService.update(id, firewall,
                    getUserId(userDetails), getClientIp(request));
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
            firewallService.delete(id, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.ok(Map.of("message", "Firewall deleted successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    private Long getUserId(UserDetails u) {
        return userRepository.findByUsername(u.getUsername()).map(user -> user.getId()).orElse(null);
    }

    private String getClientIp(HttpServletRequest r) {
        String xff = r.getHeader("X-Forwarded-For");
        return (xff != null && !xff.isEmpty()) ? xff.split(",")[0].trim() : r.getRemoteAddr();
    }
}
