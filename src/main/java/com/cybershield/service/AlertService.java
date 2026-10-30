package com.cybershield.service;

import com.cybershield.model.Incident;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/**
 * AlertService — ENHANCEMENT (Part 1, #2 Email Alerting).
 *
 * Sends an email notification the moment a HIGH or CRITICAL incident is
 * created, so SOC admins don't have to keep the dashboard open to notice
 * a serious event.
 *
 * Safe-by-default: if alert.email.enabled=false (the default, so the
 * project still runs with zero setup) this just logs what WOULD have
 * been sent instead of calling SMTP. Flip it on in application.properties
 * once real SMTP credentials are configured.
 */
@Service
@Slf4j
public class AlertService {

    private final JavaMailSender mailSender;

    @Value("${alert.email.enabled:false}")
    private boolean enabled;

    @Value("${alert.email.to:soc-team@example.com}")
    private String toAddress;

    @Value("${alert.email.from:cybershield-nexus@example.com}")
    private String fromAddress;

    public AlertService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    /**
     * Fire-and-forget alert for a newly created incident. Only triggers
     * for HIGH/CRITICAL severity — LOW/MEDIUM stay dashboard-only to
     * avoid alert fatigue.
     */
    public void sendIncidentAlert(Incident incident) {
        if (incident == null) return;

        boolean isSeriousEnough = incident.getSeverity() == Incident.Severity.HIGH
                || incident.getSeverity() == Incident.Severity.CRITICAL;
        if (!isSeriousEnough) {
            return;
        }

        String subject = String.format("[CyberShield Nexus] %s Incident #%d — %s",
                incident.getSeverity(), incident.getId(), incident.getTitle());

        String body = String.format(
                "A %s severity incident was just created in CyberShield Nexus.%n%n" +
                "Incident ID : %d%n" +
                "Title       : %s%n" +
                "Risk Score  : %d/100%n" +
                "Status      : %s%n" +
                "Description : %s%n%n" +
                "Login to the dashboard to investigate: http://localhost:8081/incidents.html",
                incident.getSeverity(), incident.getId(), incident.getTitle(),
                incident.getRiskScore(), incident.getStatus(), incident.getDescription());

        if (!enabled) {
            log.info("[ALERT-SIMULATED] Email alerts disabled (alert.email.enabled=false). " +
                    "Would have sent to '{}': subject='{}'", toAddress, subject);
            return;
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromAddress);
            message.setTo(toAddress);
            message.setSubject(subject);
            message.setText(body);
            mailSender.send(message);
            log.info("Email alert sent to '{}' for incident #{}", toAddress, incident.getId());
        } catch (MailException e) {
            // Never let an alerting failure break incident creation
            log.error("Failed to send email alert for incident #{}: {}", incident.getId(), e.getMessage());
        }
    }
}
