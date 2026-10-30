package com.cybershield.controller;

import com.cybershield.model.DigitalService;
import com.cybershield.model.DigitalService.ServiceStatus;
import com.cybershield.service.DigitalServiceService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * DigitalServiceController -- REST API for NEDI digital service management.
 *
 * GET  /api/services                   -> list all 8 NEDI services
 * GET  /api/services/high-risk         -> services in HIGH_RISK or DOWN state
 * GET  /api/services/summary           -> count summary (healthy/degraded/highRisk/critical)
 * PATCH /api/services/{code}/status    -> update service health status (ADMIN only)
 */
@RestController
@RequestMapping("/api/services")
@RequiredArgsConstructor
public class DigitalServiceController {

    private final DigitalServiceService digitalServiceService;

    /** List all NEDI digital services */
    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<DigitalService>> getAllServices() {
        return ResponseEntity.ok(digitalServiceService.getAllServices());
    }

    /** List services that are HIGH_RISK or DOWN */
    @GetMapping("/high-risk")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<DigitalService>> getHighRiskServices() {
        return ResponseEntity.ok(digitalServiceService.getHighRiskServices());
    }

    /** Count summary: healthy / degraded / highRisk / critical */
    @GetMapping("/summary")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<Map<String, Object>> getSummary() {
        Map<String, Object> summary = Map.of(
                "total",           digitalServiceService.countTotal(),
                "healthy",         digitalServiceService.countByStatus(ServiceStatus.HEALTHY),
                "degraded",        digitalServiceService.countByStatus(ServiceStatus.DEGRADED),
                "highRisk",        digitalServiceService.countByStatus(ServiceStatus.HIGH_RISK)
                                 + digitalServiceService.countByStatus(ServiceStatus.DOWN),
                "criticalServices",digitalServiceService.countCriticalServices()
        );
        return ResponseEntity.ok(summary);
    }

    /**
     * Update a service health status by service code.
     * Example: PATCH /api/services/EXAM_PORTAL/status?status=HEALTHY
     */
    @PatchMapping("/{serviceCode}/status")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<DigitalService> updateStatus(
            @PathVariable String serviceCode,
            @RequestParam ServiceStatus status) {
        DigitalService updated = digitalServiceService.updateStatus(serviceCode, status);
        return ResponseEntity.ok(updated);
    }
}
