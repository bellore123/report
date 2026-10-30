package com.cybershield.repository;

import com.cybershield.model.Firewall;
import com.cybershield.model.Firewall.FirewallStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FirewallRepository extends JpaRepository<Firewall, Long> {

    List<Firewall> findByStatus(FirewallStatus status);

    long countByStatus(FirewallStatus status);
}
