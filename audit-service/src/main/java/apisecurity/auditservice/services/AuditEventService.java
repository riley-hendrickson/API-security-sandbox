package apisecurity.auditservice.services;

import apisecurity.auditservice.exceptions.CallerUnauthorizedException;
import apisecurity.auditservice.exceptions.MalformedRequestException;
import apisecurity.auditservice.dtos.AuditEventRequest;
import apisecurity.auditservice.entities.AuditEvent;
import apisecurity.auditservice.enums.Action;
import apisecurity.auditservice.enums.CallerKind;
import apisecurity.auditservice.repositories.AuditEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

@Service
public class AuditEventService
{
    private final AuditEventRepository auditEventRepository;
    private final Clock clock;
    private static final Logger log = LoggerFactory.getLogger(AuditEventService.class);

    public AuditEventService(AuditEventRepository auditEventRepository, Clock clock)
    {
        this.auditEventRepository = auditEventRepository;
        this.clock = clock;
    }

    @Transactional
    public void createAuditEvent(Jwt jwt, AuditEventRequest auditEventRequest)
    {
        CallerKind callerKind = CallerKind.from(jwt);
        // Caller is the system
        if (callerKind == CallerKind.SYSTEM)
        {
            if (auditEventRequest.action() != Action.SYSTEM_SNAPSHOT) throw new CallerUnauthorizedException("System token can only be used for system snapshots");
            if (auditEventRequest.documentId() != null) throw new MalformedRequestException("System token can't be used for document actions");

            auditEventRepository.save(
                    new AuditEvent(Instant.now(clock), auditEventRequest.action(), null, null, jwt.getClaimAsString("azp"), CallerKind.SYSTEM));
        }
        // Caller is a user
        else
        {
            if (Action.SYSTEM_SNAPSHOT.equals(auditEventRequest.action()))
                throw new CallerUnauthorizedException("User token can't be used for system snapshots");
            if (auditEventRequest.documentId() == null)
                throw new MalformedRequestException("User token must contain document id");

            auditEventRepository.save(
                    new AuditEvent(Instant.now(clock), auditEventRequest.action(), auditEventRequest.documentId(), jwt.getSubject(), jwt.getClaimAsString("azp"), CallerKind.USER));
            log.info("Recorded USER {} doc={} actor={} viaClient{}",  auditEventRequest.action(), auditEventRequest.documentId(), jwt.getSubject(), jwt.getClaimAsString("azp"));
        }
    }
}
