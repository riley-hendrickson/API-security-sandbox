package apisecurity.docsapi.dtos;

import java.util.Set;

public record DocumentResponse(Long documentId, String ownerId, Set<String> sharedWith, String title, String content)
{
}
