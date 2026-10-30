package com.cybershield.controller;

import com.cybershield.model.FirewallRule;
import com.cybershield.repository.UserRepository;
import com.cybershield.service.FirewallRuleService;
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
 * FirewallRuleController — NEW MODULE (PS point 6).
 *
 * Endpoints:
 *   GET    /api/firewalls/{firewallId}/rules   → list rules for a firewall
 *   POST   /api/firewalls/{firewallId}/rules   → add a rule
 *   PUT    /api/firewall-rules/{id}            → edit a rule
 *   DELETE /api/firewall-rules/{id}             → remove a rule
 *
 * RBAC follows the same pattern as FirewallController.
 */
@RestController
@RequiredArgsConstructor
public class FirewallRuleController {

    private final FirewallRuleService firewallRuleService;
    private final UserRepository userRepository;

    @GetMapping("/api/firewalls/{firewallId}/rules")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<FirewallRule>> getRules(@PathVariable Long firewallId) {
        return ResponseEntity.ok(firewallRuleService.getRulesForFirewall(firewallId));
    }

    @PostMapping("/api/firewalls/{firewallId}/rules")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> createRule(@PathVariable Long firewallId,
                                         @RequestBody FirewallRule rule,
                                         @AuthenticationPrincipal UserDetails userDetails,
                                         HttpServletRequest request) {
        try {
            FirewallRule created = firewallRuleService.create(firewallId, rule, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/api/firewall-rules/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> updateRule(@PathVariable Long id,
                                         @RequestBody FirewallRule rule,
                                         @AuthenticationPrincipal UserDetails userDetails,
                                         HttpServletRequest request) {
        try {
            FirewallRule updated = firewallRuleService.update(id, rule, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.ok(updated);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @DeleteMapping("/api/firewall-rules/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> deleteRule(@PathVariable Long id,
                                         @AuthenticationPrincipal UserDetails userDetails,
                                         HttpServletRequest request) {
        try {
            firewallRuleService.delete(id, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.ok(Map.of("message", "Rule deleted successfully"));
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
