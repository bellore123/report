package com.cybershield.repository;

import com.cybershield.model.LoadBalancerBackend;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LoadBalancerBackendRepository extends JpaRepository<LoadBalancerBackend, Long> {

    List<LoadBalancerBackend> findByLoadBalancerId(Long loadBalancerId);

    long countByLoadBalancerId(Long loadBalancerId);

    long countByLoadBalancerIdAndHealthyTrue(Long loadBalancerId);
}
