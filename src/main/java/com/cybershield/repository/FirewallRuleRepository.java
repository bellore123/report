package com.cybershield.repository;

import com.cybershield.model.FirewallRule;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FirewallRuleRepository extends JpaRepository<FirewallRule, Long> {

    List<FirewallRule> findByFirewallIdOrderByPriorityAsc(Long firewallId);

    long countByFirewallId(Long firewallId);
}
