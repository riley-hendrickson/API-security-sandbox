package apisecurity.docsapi.jobs;

import apisecurity.docsapi.clients.AuditClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class SystemSnapshotJob
{
    private final AuditClient auditClient;

    public SystemSnapshotJob(AuditClient auditClient)
    {
        this.auditClient = auditClient;
    }

    @Scheduled(fixedRateString = "${app.audit.snapshot-rate-ms:60000}")
    public void recordSnapshot()
    {
        auditClient.recordSystemEvent();
    }
}
