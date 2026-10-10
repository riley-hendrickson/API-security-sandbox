package apisecurity.docsapi.dtos;


import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.Set;

public record ShareRequest(@NotNull Set<@NotBlank String> userIds)
{
}
