package com.cybershield.controller;

import com.cybershield.model.Institution;
import com.cybershield.service.InstitutionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * InstitutionController -- REST API for NEDI institution management.
 *
 * GET /api/institutions              -> all institutions
 * GET /api/institutions/at-risk      -> degraded / high-risk / offline institutions
 * GET /api/institutions/{code}       -> single institution by institution code
 */
@RestController
@RequestMapping("/api/institutions")
@RequiredArgsConstructor
public class InstitutionController {

    private final InstitutionService institutionService;

    /** List all NEDI representative institutions */
    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<Institution>> getAll() {
        return ResponseEntity.ok(institutionService.getAll());
    }

    /** List institutions in degraded / high-risk / offline state */
    @GetMapping("/at-risk")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<Institution>> getAtRisk() {
        return ResponseEntity.ok(institutionService.getAtRiskInstitutions());
    }

    /** Get single institution by code (e.g. NEDI-CENTRAL, COL-A-SOUTH) */
    @GetMapping("/{institutionCode}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<Institution> getByCode(@PathVariable String institutionCode) {
        return institutionService.findByCode(institutionCode)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
