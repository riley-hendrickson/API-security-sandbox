package apisecurity.backendforfrontend.controllers;

import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClient.RequestHeadersSpec.ConvertibleClientHttpResponse;

import java.io.IOException;
import java.util.List;

@RestController
public class RelayController
{
    private final RestClient docsApiClient;

    public RelayController(RestClient docsApiClient)
    {
        this.docsApiClient = docsApiClient;
    }

    @GetMapping("/api/documents/{documentId}")
    public ResponseEntity<String> getDocument(@PathVariable Long documentId)
    {
        return docsApiClient.get()
                .uri("/documents/{id}", documentId)
                .exchange((request, response) ->
                {
                   return ResponseEntity.status(response.getStatusCode()).body(response.bodyTo(String.class));
                });
    }

    private ResponseEntity<String> relay(HttpRequest request,
                                         ConvertibleClientHttpResponse response) throws IOException
    {
        
    }
}
