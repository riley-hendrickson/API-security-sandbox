package apisecurity.auditservice.controllers;

import apisecurity.auditservice.dtos.AuditEventRequest;
import apisecurity.auditservice.services.AuditEventService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/audit-events")
public class AuditEventsController
{
    private final AuditEventService auditEventService;

    public AuditEventsController(AuditEventService auditEventService)
    {
        this.auditEventService = auditEventService;
    }

    @PostMapping()
    public ResponseEntity<Void> newAuditEvent(@AuthenticationPrincipal Jwt jwt, @RequestBody @Valid AuditEventRequest auditEventRequest)
    {
        auditEventService.createAuditEvent(jwt, auditEventRequest);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
}
