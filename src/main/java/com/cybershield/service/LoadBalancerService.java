package com.cybershield.service;

import com.cybershield.model.AuditLog.Action;
import com.cybershield.model.AuditLog.TargetType;
import com.cybershield.model.LoadBalancer;
import com.cybershield.model.LoadBalancerBackend;
import com.cybershield.repository.LoadBalancerBackendRepository;
import com.cybershield.repository.LoadBalancerRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class LoadBalancerService {

    private final LoadBalancerRepository loadBalancerRepository;
    private final LoadBalancerBackendRepository backendRepository;
    private final AuditLogService auditLogService;

    // ── Load Balancer CRUD ─────────────────────────────────────────────

    public List<LoadBalancer> getAll() {
        return loadBalancerRepository.findAll();
    }

    public LoadBalancer getById(Long id) {
        return loadBalancerRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Load balancer not found with id: " + id));
    }

    public LoadBalancer create(LoadBalancer lb, Long actorUserId, String ip) {
        LoadBalancer saved = loadBalancerRepository.save(lb);
        auditLogService.log(actorUserId, Action.CREATE, TargetType.LOAD_BALANCER, saved.getId(), ip,
                "Created load balancer: " + saved.getName());
        return saved;
    }

    public LoadBalancer update(Long id, LoadBalancer updated, Long actorUserId, String ip) {
        LoadBalancer existing = getById(id);
        existing.setName(updated.getName());
        existing.setVirtualIp(updated.getVirtualIp());
        existing.setAlgorithm(updated.getAlgorithm());
        existing.setStatus(updated.getStatus());
        existing.setHealthCheckPath(updated.getHealthCheckPath());
        existing.setHealthCheckIntervalSeconds(updated.getHealthCheckIntervalSeconds());
        existing.setNotes(updated.getNotes());
        LoadBalancer saved = loadBalancerRepository.save(existing);
        auditLogService.log(actorUserId, Action.UPDATE, TargetType.LOAD_BALANCER, id, ip,
                "Updated load balancer: " + saved.getName());
        return saved;
    }

    public void delete(Long id, Long actorUserId, String ip) {
        LoadBalancer lb = getById(id);
        loadBalancerRepository.deleteById(id);
        auditLogService.log(actorUserId, Action.DELETE, TargetType.LOAD_BALANCER, id, ip,
                "Deleted load balancer: " + lb.getName());
    }

    public long countTotal() { return loadBalancerRepository.count(); }

    public long countActive() { return loadBalancerRepository.countByStatus(LoadBalancer.LbStatus.ACTIVE); }

    // ── Backend pool management ────────────────────────────────────────

    public List<LoadBalancerBackend> getBackends(Long loadBalancerId) {
        return backendRepository.findByLoadBalancerId(loadBalancerId);
    }

    public LoadBalancerBackend addBackend(Long loadBalancerId, LoadBalancerBackend backend,
                                           Long actorUserId, String ip) {
        LoadBalancer lb = getById(loadBalancerId);
        backend.setId(null);
        backend.setLoadBalancer(lb);
        LoadBalancerBackend saved = backendRepository.save(backend);
        auditLogService.log(actorUserId, Action.CREATE, TargetType.LOAD_BALANCER, loadBalancerId, ip,
                "Added backend '" + saved.getTargetName() + "' to load balancer " + lb.getName());
        return saved;
    }

    /** Toggle a backend's health status (simulates a health-check result). */
    public LoadBalancerBackend setBackendHealth(Long backendId, boolean healthy, Long actorUserId, String ip) {
        LoadBalancerBackend backend = backendRepository.findById(backendId)
                .orElseThrow(() -> new RuntimeException("Backend not found with id: " + backendId));
        backend.setHealthy(healthy);
        LoadBalancerBackend saved = backendRepository.save(backend);
        auditLogService.log(actorUserId, Action.UPDATE, TargetType.LOAD_BALANCER,
                backend.getLoadBalancer() != null ? backend.getLoadBalancer().getId() : null, ip,
                "Backend '" + saved.getTargetName() + "' marked " + (healthy ? "HEALTHY" : "UNHEALTHY"));
        return saved;
    }

    public void removeBackend(Long backendId, Long actorUserId, String ip) {
        LoadBalancerBackend backend = backendRepository.findById(backendId)
                .orElseThrow(() -> new RuntimeException("Backend not found with id: " + backendId));
        Long lbId = backend.getLoadBalancer() != null ? backend.getLoadBalancer().getId() : null;
        backendRepository.deleteById(backendId);
        auditLogService.log(actorUserId, Action.DELETE, TargetType.LOAD_BALANCER, lbId, ip,
                "Removed backend '" + backend.getTargetName() + "'");
    }

    public long countHealthyBackends(Long loadBalancerId) {
        return backendRepository.countByLoadBalancerIdAndHealthyTrue(loadBalancerId);
    }

    public long countTotalBackends(Long loadBalancerId) {
        return backendRepository.countByLoadBalancerId(loadBalancerId);
    }
}
