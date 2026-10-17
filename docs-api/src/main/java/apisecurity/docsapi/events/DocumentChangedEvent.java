package apisecurity.docsapi.events;

import apisecurity.docsapi.enums.AuditAction;

public record DocumentChangedEvent(AuditAction action, Long documentId) {}
