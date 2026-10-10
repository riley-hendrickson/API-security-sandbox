package apisecurity.docsapi.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record UpdateDocumentRequest(@NotBlank String title, @NotNull String content)
{
}
