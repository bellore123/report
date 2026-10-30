package com.cybershield.controller;

import com.cybershield.model.License;
import com.cybershield.repository.UserRepository;
import com.cybershield.service.LicenseService;
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
 * LicenseController — REST API for Software License management.
 *
 * RBAC:
 *   GET    → ADMIN, SERVER_ADMIN, VIEWER
 *   POST/PUT → ADMIN only (license purchasing is admin responsibility)
 *   DELETE → ADMIN only
 */
@RestController
@RequestMapping("/api/licenses")
@RequiredArgsConstructor
public class LicenseController {

    private final LicenseService licenseService;
    private final UserRepository userRepository;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<License>> getAll() {
        return ResponseEntity.ok(licenseService.getAll());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<?> getById(@PathVariable Long id) {
        try {
            return ResponseEntity.ok(licenseService.getById(id));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    // Dashboard helpers — expired and expiring soon lists
    @GetMapping("/expired")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<License>> getExpired() {
        return ResponseEntity.ok(licenseService.getExpiredLicenses());
    }

    @GetMapping("/expiring-soon")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<License>> getExpiringSoon() {
        return ResponseEntity.ok(licenseService.getExpiringSoon());
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> create(@RequestBody License license,
                                    @AuthenticationPrincipal UserDetails userDetails,
                                    HttpServletRequest request) {
        try {
            License created = licenseService.create(license,
                    getUserId(userDetails), getClientIp(request));
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> update(@PathVariable Long id,
                                    @RequestBody License license,
                                    @AuthenticationPrincipal UserDetails userDetails,
                                    HttpServletRequest request) {
        try {
            License updated = licenseService.update(id, license,
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
            licenseService.delete(id, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.ok(Map.of("message", "License deleted successfully"));
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
