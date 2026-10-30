package com.cybershield.service;

import com.cybershield.model.AuditLog.Action;
import com.cybershield.model.AuditLog.TargetType;
import com.cybershield.model.Firewall;
import com.cybershield.repository.FirewallRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class FirewallService {

    private final FirewallRepository firewallRepository;
    private final AuditLogService auditLogService;

    public List<Firewall> getAll() {
        return firewallRepository.findAll();
    }

    public Firewall getById(Long id) {
        return firewallRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Firewall not found with id: " + id));
    }

    public Firewall create(Firewall firewall, Long actorUserId, String ip) {
        Firewall saved = firewallRepository.save(firewall);
        auditLogService.log(actorUserId, Action.CREATE, TargetType.FIREWALL, saved.getId(), ip,
                "Created firewall: " + saved.getName());
        return saved;
    }

    public Firewall update(Long id, Firewall updated, Long actorUserId, String ip) {
        Firewall existing = getById(id);
        existing.setName(updated.getName());
        existing.setVendor(updated.getVendor());
        existing.setModel(updated.getModel());
        existing.setIpAddress(updated.getIpAddress());
        existing.setFirmwareVersion(updated.getFirmwareVersion());
        existing.setStatus(updated.getStatus());
        existing.setLocation(updated.getLocation());
        existing.setActiveRulesCount(updated.getActiveRulesCount());
        existing.setLastRuleReviewDate(updated.getLastRuleReviewDate());
        existing.setLastFirmwareUpdate(updated.getLastFirmwareUpdate());
        existing.setWarrantyExpiry(updated.getWarrantyExpiry());
        existing.setNotes(updated.getNotes());
        Firewall saved = firewallRepository.save(existing);
        auditLogService.log(actorUserId, Action.UPDATE, TargetType.FIREWALL, id, ip,
                "Updated firewall: " + saved.getName());
        return saved;
    }

    public void delete(Long id, Long actorUserId, String ip) {
        Firewall fw = getById(id);
        firewallRepository.deleteById(id);
        auditLogService.log(actorUserId, Action.DELETE, TargetType.FIREWALL, id, ip,
                "Deleted firewall: " + fw.getName());
    }

    public long countTotal() { return firewallRepository.count(); }

    public long countActive() {
        return firewallRepository.countByStatus(Firewall.FirewallStatus.ACTIVE);
    }
}
