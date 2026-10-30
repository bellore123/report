package com.cybershield.service;

import com.cybershield.model.AuditLog.Action;
import com.cybershield.model.AuditLog.TargetType;
import com.cybershield.model.Firewall;
import com.cybershield.model.FirewallRule;
import com.cybershield.repository.FirewallRepository;
import com.cybershield.repository.FirewallRuleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class FirewallRuleService {

    private final FirewallRuleRepository firewallRuleRepository;
    private final FirewallRepository firewallRepository;
    private final AuditLogService auditLogService;

    public List<FirewallRule> getRulesForFirewall(Long firewallId) {
        return firewallRuleRepository.findByFirewallIdOrderByPriorityAsc(firewallId);
    }

    public FirewallRule create(Long firewallId, FirewallRule rule, Long actorUserId, String ip) {
        Firewall firewall = firewallRepository.findById(firewallId)
                .orElseThrow(() -> new RuntimeException("Firewall not found with id: " + firewallId));
        rule.setId(null);
        rule.setFirewall(firewall);
        FirewallRule saved = firewallRuleRepository.save(rule);
        syncActiveRulesCount(firewall);
        auditLogService.log(actorUserId, Action.CREATE, TargetType.FIREWALL_RULE, saved.getId(), ip,
                "Created firewall rule '" + saved.getName() + "' on " + firewall.getName());
        return saved;
    }

    public FirewallRule update(Long id, FirewallRule updated, Long actorUserId, String ip) {
        FirewallRule existing = firewallRuleRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Firewall rule not found with id: " + id));
        existing.setName(updated.getName());
        existing.setSourceIp(updated.getSourceIp());
        existing.setDestinationIp(updated.getDestinationIp());
        existing.setPort(updated.getPort());
        existing.setProtocol(updated.getProtocol());
        existing.setAction(updated.getAction());
        existing.setPriority(updated.getPriority());
        existing.setEnabled(updated.isEnabled());
        existing.setDescription(updated.getDescription());
        FirewallRule saved = firewallRuleRepository.save(existing);
        auditLogService.log(actorUserId, Action.UPDATE, TargetType.FIREWALL_RULE, id, ip,
                "Updated firewall rule '" + saved.getName() + "'");
        return saved;
    }

    public void delete(Long id, Long actorUserId, String ip) {
        FirewallRule rule = firewallRuleRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Firewall rule not found with id: " + id));
        Firewall firewall = rule.getFirewall();
        firewallRuleRepository.deleteById(id);
        if (firewall != null) syncActiveRulesCount(firewall);
        auditLogService.log(actorUserId, Action.DELETE, TargetType.FIREWALL_RULE, id, ip,
                "Deleted firewall rule '" + rule.getName() + "'");
    }

    /** Keeps the legacy Firewall.activeRulesCount field in sync with real rule rows. */
    private void syncActiveRulesCount(Firewall firewall) {
        long count = firewallRuleRepository.countByFirewallId(firewall.getId());
        firewall.setActiveRulesCount((int) count);
        firewallRepository.save(firewall);
    }
}
