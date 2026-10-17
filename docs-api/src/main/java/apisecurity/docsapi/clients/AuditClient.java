package apisecurity.docsapi.clients;

import apisecurity.docsapi.enums.AuditAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;


@Component
public class AuditClient
{
    private static final Logger log = LoggerFactory.getLogger(AuditClient.class);

    public record AuditEventRequest(AuditAction action, Long documentId){}

    private final RestClient auditOnBehalfClient;

    public AuditClient(@Qualifier("auditOnBehalfClient") RestClient auditOnBehalfClient)
    {
        this.auditOnBehalfClient = auditOnBehalfClient;
    }

    public void recordDocumentEvent(AuditAction action, Long documentId)
    {
        try
        {
            auditOnBehalfClient.post()
                    .uri("/audit-events")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new AuditEventRequest(action, documentId))
                    .retrieve()
                    .toBodilessEntity();
        }
        catch(RestClientResponseException e)
        {
            // audit service rejected the request, which means the bug is on our side
            log.error("Audit event rejected: action={}, documentId={}, status={}", action, documentId, e.getStatusCode());
        }
        catch(RestClientException e)
        {
            log.warn("Audit service not available, event not recorded: action={}, documentId={}, error message={}", action, documentId, e.getMessage());
        }
        catch(OAuth2AuthorizationException e)
        {
            log.error("Could not obtain audit token: action={}, documentId={}, error={}", action, documentId, e.getError().getErrorCode());
        }
    }
}
