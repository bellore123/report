package com.cybershield.controller;

import com.cybershield.model.Incident;
import com.cybershield.service.IncidentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * IncidentController — REST API for viewing and managing security incidents.
 *
 * Endpoints:
 *   GET  /api/incidents            → all recent incidents (ADMIN, SERVER_ADMIN)
 *   GET  /api/incidents/open       → open incidents only
 *   GET  /api/incidents/count      → count of open incidents (dashboard badge)
 *   PUT  /api/incidents/{id}/resolve      → mark as RESOLVED (ADMIN only)
 *   PUT  /api/incidents/{id}/investigate  → mark as INVESTIGATING
 */
@RestController
@RequestMapping("/api/incidents")
@RequiredArgsConstructor
public class IncidentController {

    private final IncidentService incidentService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<Incident>> getAllIncidents() {
        return ResponseEntity.ok(incidentService.getAllIncidents());
    }

    @GetMapping("/open")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<Incident>> getOpenIncidents() {
        return ResponseEntity.ok(incidentService.getOpenIncidents());
    }

    @GetMapping("/count")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<Map<String, Long>> getOpenCount() {
        return ResponseEntity.ok(Map.of("openIncidents", incidentService.countOpenIncidents()));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<?> getIncidentById(@PathVariable Long id) {
        return incidentService.getAllIncidents().stream()
                .filter(i -> i.getId().equals(id))
                .findFirst()
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/{id}/investigate")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> investigate(@PathVariable Long id,
                                         @RequestBody(required = false) Map<String, String> body,
                                         @AuthenticationPrincipal UserDetails userDetails) {
        try {
            String assignee = body != null && body.containsKey("assignedTo") ? body.get("assignedTo") : (userDetails != null ? userDetails.getUsername() : "soc-analyst");
            return ResponseEntity.ok(incidentService.markInvestigating(id, assignee));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}/contain")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> contain(@PathVariable Long id,
                                     @RequestBody(required = false) Map<String, String> body,
                                     @AuthenticationPrincipal UserDetails userDetails) {
        try {
            String responder = userDetails != null ? userDetails.getUsername() : "soc-admin";
            String notes = body != null ? body.getOrDefault("notes", "Compromised ingress isolated; service traffic rerouted.") : "Service contained";
            Incident contained = incidentService.containIncident(id, responder, notes);
            return ResponseEntity.ok(contained);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}/resolve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> resolve(@PathVariable Long id,
                                     @RequestBody(required = false) Map<String, String> body,
                                     @AuthenticationPrincipal UserDetails userDetails) {
        try {
            String resolver = userDetails != null ? userDetails.getUsername() : "admin";
            String notes = body != null ? body.getOrDefault("notes", "Remediation verified; system returned to healthy baseline.") : null;
            Incident resolved = incidentService.resolveIncident(id, resolver, notes);
            return ResponseEntity.ok(resolved);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}/notes")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> updateNotes(@PathVariable Long id,
                                         @RequestBody Map<String, String> body) {
        try {
            String notes = body.getOrDefault("notes", "");
            return ResponseEntity.ok(incidentService.updateRemediationNotes(id, notes));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
