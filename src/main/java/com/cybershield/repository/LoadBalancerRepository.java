package com.cybershield.repository;

import com.cybershield.model.LoadBalancer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LoadBalancerRepository extends JpaRepository<LoadBalancer, Long> {

    long countByStatus(LoadBalancer.LbStatus status);
}
