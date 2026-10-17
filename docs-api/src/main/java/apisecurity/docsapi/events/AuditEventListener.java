package apisecurity.docsapi.events;

import apisecurity.docsapi.clients.AuditClient;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
public class AuditEventListener
{
    private final AuditClient auditClient;

    public AuditEventListener(AuditClient auditClient)
    {
        this.auditClient = auditClient;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onDocumentChanged(DocumentChangedEvent event)
    {
        auditClient.recordDocumentEvent(event.action(), event.documentId());
    }
}
