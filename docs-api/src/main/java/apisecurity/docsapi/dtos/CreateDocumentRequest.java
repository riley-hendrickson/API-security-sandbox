package apisecurity.docsapi.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record CreateDocumentRequest(@NotBlank String title, @NotNull String content)
{
}
