package com.cybershield.service;

import com.cybershield.model.AuditLog.Action;
import com.cybershield.model.AuditLog.TargetType;
import com.cybershield.model.Server;
import com.cybershield.repository.ServerRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;

/**
 * ServerService — business logic for server CRUD operations.
 * Every write action is logged to AuditLog.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ServerService {

    private final ServerRepository serverRepository;
    private final AuditLogService auditLogService;

    public List<Server> getAll() {
        return serverRepository.findAll();
    }

    public Server getById(Long id) {
        return serverRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Server not found with id: " + id));
    }

    public Server create(Server server, Long actorUserId, String ip) {
        if (serverRepository.existsByIpAddress(server.getIpAddress())) {
            throw new RuntimeException("Server with IP " + server.getIpAddress() + " already exists");
        }
        Server saved = serverRepository.save(server);
        auditLogService.log(actorUserId, Action.CREATE, TargetType.SERVER, saved.getId(), ip,
                "Created server: " + saved.getName());
        log.info("Server created: {} ({})", saved.getName(), saved.getIpAddress());
        return saved;
    }

    public Server update(Long id, Server updated, Long actorUserId, String ip) {
        Server existing = getById(id);
        existing.setName(updated.getName());
        existing.setIpAddress(updated.getIpAddress());
        existing.setOperatingSystem(updated.getOperatingSystem());
        existing.setOsVersion(updated.getOsVersion());
        existing.setStatus(updated.getStatus());
        existing.setLocation(updated.getLocation());
        existing.setOwner(updated.getOwner());
        existing.setCpuCores(updated.getCpuCores());
        existing.setRamGb(updated.getRamGb());
        existing.setStorageGb(updated.getStorageGb());
        existing.setLastPatchDate(updated.getLastPatchDate());
        existing.setWarrantyExpiry(updated.getWarrantyExpiry());
        existing.setNotes(updated.getNotes());
        Server saved = serverRepository.save(existing);
        auditLogService.log(actorUserId, Action.UPDATE, TargetType.SERVER, id, ip,
                "Updated server: " + saved.getName());
        return saved;
    }

    public void delete(Long id, Long actorUserId, String ip) {
        Server server = getById(id);
        serverRepository.deleteById(id);
        auditLogService.log(actorUserId, Action.DELETE, TargetType.SERVER, id, ip,
                "Deleted server: " + server.getName());
        log.info("Server deleted: id={}", id);
    }

    // Risk Engine support: get servers not patched in last 90 days
    public List<Server> getUnpatchedServers() {
        LocalDate cutoff = LocalDate.now().minusDays(90);
        return serverRepository.findUnpatchedServersBefore(cutoff);
    }

    // Dashboard stats
    public long countRunning() {
        return serverRepository.countByStatus(Server.ServerStatus.RUNNING);
    }

    public long countTotal() {
        return serverRepository.count();
    }
}
