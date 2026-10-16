package apisecurity.auditservice.dtos;

import apisecurity.auditservice.enums.Action;
import jakarta.validation.constraints.NotNull;

public record AuditEventRequest(@NotNull Action action, Long documentId)
{
}
