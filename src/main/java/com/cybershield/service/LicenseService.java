package com.cybershield.service;

import com.cybershield.model.AuditLog.Action;
import com.cybershield.model.AuditLog.TargetType;
import com.cybershield.model.License;
import com.cybershield.repository.LicenseRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class LicenseService {

    private final LicenseRepository licenseRepository;
    private final AuditLogService auditLogService;

    public List<License> getAll() {
        return licenseRepository.findAll();
    }

    public License getById(Long id) {
        return licenseRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("License not found with id: " + id));
    }

    public License create(License license, Long actorUserId, String ip) {
        License saved = licenseRepository.save(license);
        auditLogService.log(actorUserId, Action.CREATE, TargetType.LICENSE, saved.getId(), ip,
                "Created license: " + saved.getSoftwareName());
        return saved;
    }

    public License update(Long id, License updated, Long actorUserId, String ip) {
        License existing = getById(id);
        existing.setSoftwareName(updated.getSoftwareName());
        existing.setVendor(updated.getVendor());
        existing.setLicenseKey(updated.getLicenseKey());
        existing.setLicenseType(updated.getLicenseType());
        existing.setTotalSeats(updated.getTotalSeats());
        existing.setUsedSeats(updated.getUsedSeats());
        existing.setExpiryDate(updated.getExpiryDate());
        existing.setPurchaseDate(updated.getPurchaseDate());
        existing.setRenewalCost(updated.getRenewalCost());
        existing.setAssignedTo(updated.getAssignedTo());
        existing.setStatus(updated.getStatus());
        existing.setNotes(updated.getNotes());
        License saved = licenseRepository.save(existing);
        auditLogService.log(actorUserId, Action.UPDATE, TargetType.LICENSE, id, ip,
                "Updated license: " + saved.getSoftwareName());
        return saved;
    }

    public void delete(Long id, Long actorUserId, String ip) {
        License lic = getById(id);
        licenseRepository.deleteById(id);
        auditLogService.log(actorUserId, Action.DELETE, TargetType.LICENSE, id, ip,
                "Deleted license: " + lic.getSoftwareName());
    }

    // Dashboard: expired licenses list
    public List<License> getExpiredLicenses() {
        return licenseRepository.findExpiredLicenses(LocalDate.now());
    }

    // Dashboard: expiring in 30 days
    public List<License> getExpiringSoon() {
        return licenseRepository.findExpiringSoon(
                LocalDate.now(),
                LocalDate.now().plusDays(30)
        );
    }

    public long countExpired() {
        return licenseRepository.countExpiredLicenses(LocalDate.now());
    }

    public long countTotal() { return licenseRepository.count(); }
}
