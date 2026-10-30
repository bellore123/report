package com.cybershield.controller;

import com.cybershield.model.LoadBalancer;
import com.cybershield.model.LoadBalancerBackend;
import com.cybershield.repository.UserRepository;
import com.cybershield.service.LoadBalancerService;
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
 * LoadBalancerController — NEW MODULE (PS point 7: Load Balancer
 * Management — "configuration, monitoring, and scaling of load
 * balancers to ensure optimal performance, high availability, and
 * efficient resource utilization").
 *
 * RBAC follows the same pattern as the other asset controllers:
 *   GET      → ADMIN, SERVER_ADMIN, VIEWER
 *   POST/PUT → ADMIN, SERVER_ADMIN
 *   DELETE   → ADMIN only
 */
@RestController
@RequiredArgsConstructor
public class LoadBalancerController {

    private final LoadBalancerService loadBalancerService;
    private final UserRepository userRepository;

    @GetMapping("/api/loadbalancers")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<LoadBalancer>> getAll() {
        return ResponseEntity.ok(loadBalancerService.getAll());
    }

    @GetMapping("/api/loadbalancers/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<?> getById(@PathVariable Long id) {
        try {
            return ResponseEntity.ok(loadBalancerService.getById(id));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/api/loadbalancers")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> create(@RequestBody LoadBalancer lb,
                                     @AuthenticationPrincipal UserDetails userDetails,
                                     HttpServletRequest request) {
        try {
            LoadBalancer created = loadBalancerService.create(lb, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/api/loadbalancers/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> update(@PathVariable Long id,
                                     @RequestBody LoadBalancer lb,
                                     @AuthenticationPrincipal UserDetails userDetails,
                                     HttpServletRequest request) {
        try {
            LoadBalancer updated = loadBalancerService.update(id, lb, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.ok(updated);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @DeleteMapping("/api/loadbalancers/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> delete(@PathVariable Long id,
                                     @AuthenticationPrincipal UserDetails userDetails,
                                     HttpServletRequest request) {
        try {
            loadBalancerService.delete(id, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.ok(Map.of("message", "Load balancer deleted successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        }
    }

    // ── Backend pool ─────────────────────────────────────────────────

    @GetMapping("/api/loadbalancers/{id}/backends")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<LoadBalancerBackend>> getBackends(@PathVariable Long id) {
        return ResponseEntity.ok(loadBalancerService.getBackends(id));
    }

    @PostMapping("/api/loadbalancers/{id}/backends")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> addBackend(@PathVariable Long id,
                                         @RequestBody LoadBalancerBackend backend,
                                         @AuthenticationPrincipal UserDetails userDetails,
                                         HttpServletRequest request) {
        try {
            LoadBalancerBackend created = loadBalancerService.addBackend(id, backend, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/api/loadbalancer-backends/{backendId}/health")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> setBackendHealth(@PathVariable Long backendId,
                                               @RequestBody Map<String, Boolean> body,
                                               @AuthenticationPrincipal UserDetails userDetails,
                                               HttpServletRequest request) {
        try {
            boolean healthy = Boolean.TRUE.equals(body.get("healthy"));
            LoadBalancerBackend updated = loadBalancerService.setBackendHealth(
                    backendId, healthy, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.ok(updated);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @DeleteMapping("/api/loadbalancer-backends/{backendId}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> removeBackend(@PathVariable Long backendId,
                                            @AuthenticationPrincipal UserDetails userDetails,
                                            HttpServletRequest request) {
        try {
            loadBalancerService.removeBackend(backendId, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.ok(Map.of("message", "Backend removed successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
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
