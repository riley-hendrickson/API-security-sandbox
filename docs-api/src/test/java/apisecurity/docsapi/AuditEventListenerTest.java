package apisecurity.docsapi;

import apisecurity.docsapi.clients.AuditClient;
import apisecurity.docsapi.enums.AuditAction;
import apisecurity.docsapi.events.AuditEventListener;
import apisecurity.docsapi.events.DocumentChangedEvent;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AuditEventListenerTest
{

    @Test
    void forwardsEventToAuditClient()
    {
        AuditClient auditClient = mock(AuditClient.class);

        new AuditEventListener(auditClient)
                .onDocumentChanged(new DocumentChangedEvent(AuditAction.DOCUMENT_SHARED, 7L));

        verify(auditClient).recordDocumentEvent(AuditAction.DOCUMENT_SHARED, 7L);
    }
}