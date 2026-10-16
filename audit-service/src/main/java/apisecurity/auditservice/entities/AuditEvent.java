package apisecurity.auditservice.entities;

import apisecurity.auditservice.enums.Action;
import apisecurity.auditservice.enums.CallerKind;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "audit_events")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuditEvent
{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false)
    private Instant occurredAt;
    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Action action;
    private Long documentId;
    private String actorUserId;
    @Column(nullable = false)
    private String viaClient;
    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private CallerKind callerKind;

    public AuditEvent(Instant occurredAt, Action action, Long documentId, String actorUserId, String viaClient, CallerKind callerKind)
    {
        this.occurredAt = occurredAt;
        this.action = action;
        this.documentId = documentId;
        this.actorUserId = actorUserId;
        this.viaClient = viaClient;
        this.callerKind = callerKind;
    }
}
