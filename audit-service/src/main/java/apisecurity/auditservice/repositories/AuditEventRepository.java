package apisecurity.auditservice.repositories;

import apisecurity.auditservice.entities.AuditEvent;
import org.springframework.data.repository.Repository;

import java.util.List;

public interface AuditEventRepository extends Repository<AuditEvent, Long>
{
    List<AuditEvent> findAll();

    AuditEvent save(AuditEvent auditEvent);
}
