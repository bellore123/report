package com.cybershield.controller;

import com.cybershield.model.Server;
import com.cybershield.repository.UserRepository;
import com.cybershield.service.ServerService;
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
 * ServerController — REST API for Server management.
 *
 * RBAC Rules:
 *   GET (read)         → ADMIN, SERVER_ADMIN, VIEWER
 *   POST/PUT (write)   → ADMIN, SERVER_ADMIN only
 *   DELETE             → ADMIN only
 *
 * Attack #2 (IDOR) is demonstrated here:
 *   VULNERABLE: GET /api/servers/{id} has no ownership check
 *   PATCHED:    Returns 403 if VIEWER tries to access server outside their scope
 */
@RestController
@RequestMapping("/api/servers")
@RequiredArgsConstructor
public class ServerController {

    private final ServerService serverService;
    private final UserRepository userRepository;

    // GET ALL — any authenticated user
    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<Server>> getAll() {
        return ResponseEntity.ok(serverService.getAll());
    }

    /**
     * GET BY ID — IDOR vulnerability is here.
     *
     * VULNERABLE version (Attack #2 demo):
     *   Only checks "isAuthenticated()" — any logged-in user can access any server ID.
     *
     * PATCHED version:
     *   VIEWER role gets 403 if they try to access a server not assigned to them.
     *   (We demo both: show 200 on vulnerable, 403 on patched)
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<?> getById(@PathVariable Long id,
                                     @AuthenticationPrincipal UserDetails userDetails,
                                     HttpServletRequest request) {
        try {
            Server server = serverService.getById(id);

            // ============================================================
            // PATCHED VERSION — uncomment this block for the fixed demo
            // Comment it out to show the VULNERABLE version (Attack #2)
            // ============================================================
            // String role = userDetails.getAuthorities().stream()
            //         .findFirst().map(a -> a.getAuthority()).orElse("");
            // if (role.equals("ROLE_VIEWER")) {
            //     // VIEWER can only see servers assigned to them
            //     if (!userDetails.getUsername().equals(server.getOwner())) {
            //         return ResponseEntity.status(HttpStatus.FORBIDDEN)
            //                 .body(Map.of("error",
            //                     "Access denied: You are not authorized to view this server"));
            //     }
            // }
            // ============================================================

            return ResponseEntity.ok(server);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    // CREATE — ADMIN and SERVER_ADMIN only
    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> create(@RequestBody Server server,
                                    @AuthenticationPrincipal UserDetails userDetails,
                                    HttpServletRequest request) {
        try {
            Long userId = getUserId(userDetails);
            String ip = getClientIp(request);
            Server created = serverService.create(server, userId, ip);
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // UPDATE — ADMIN and SERVER_ADMIN only
    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> update(@PathVariable Long id,
                                    @RequestBody Server server,
                                    @AuthenticationPrincipal UserDetails userDetails,
                                    HttpServletRequest request) {
        try {
            Long userId = getUserId(userDetails);
            Server updated = serverService.update(id, server, userId, getClientIp(request));
            return ResponseEntity.ok(updated);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // DELETE — ADMIN only
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> delete(@PathVariable Long id,
                                    @AuthenticationPrincipal UserDetails userDetails,
                                    HttpServletRequest request) {
        try {
            serverService.delete(id, getUserId(userDetails), getClientIp(request));
            return ResponseEntity.ok(Map.of("message", "Server deleted successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    private Long getUserId(UserDetails userDetails) {
        return userRepository.findByUsername(userDetails.getUsername())
                .map(u -> u.getId()).orElse(null);
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        return (xff != null && !xff.isEmpty()) ? xff.split(",")[0].trim()
                                               : request.getRemoteAddr();
    }
}
