package com.cybershield.controller;

import com.cybershield.service.ReportService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.NoSuchElementException;

/**
 * ReportController — Generates live dynamic incident and forensic reports.
 *
 * Endpoints:
 *   GET /api/reports/incident/{id}       → JSON structured report (SIEM / API)
 *   GET /api/reports/incident/{id}/html  → Executive HTML document (Printable / PDF)
 */
@RestController
@RequestMapping("/api/reports")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;

    @GetMapping("/incident/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<?> getIncidentReportJson(@PathVariable Long id) {
        try {
            Map<String, Object> report = reportService.generateIncidentReportJson(id);
            return ResponseEntity.ok(report);
        } catch (NoSuchElementException e) {
            return ResponseEntity.status(404).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping(value = "/incident/{id}/html", produces = MediaType.TEXT_HTML_VALUE)
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<String> getIncidentReportHtml(@PathVariable Long id) {
        try {
            String html = reportService.generateIncidentReportHtml(id);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.TEXT_HTML);
            return ResponseEntity.ok().headers(headers).body(html);
        } catch (NoSuchElementException e) {
            return ResponseEntity.status(404).body("<h1>404 Not Found</h1><p>" + e.getMessage() + "</p>");
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("<h1>500 Internal Server Error</h1><p>" + e.getMessage() + "</p>");
        }
    }

    // ENHANCEMENT (Part 1, #7): downloadable PDF version of the incident report
    @GetMapping(value = "/incident/{id}/pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<?> getIncidentReportPdf(@PathVariable Long id) {
        try {
            byte[] pdf = reportService.generateIncidentReportPdf(id);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("attachment", "incident-report-" + id + ".pdf");
            return ResponseEntity.ok().headers(headers).body(pdf);
        } catch (NoSuchElementException e) {
            return ResponseEntity.status(404).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }
}
