package apisecurity.docsapi.dtos;

import java.util.Set;

public record ShareRequest(Long documentId, Set<String> userIds)
{
}
