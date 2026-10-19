package apisecurity.backendforfrontend.controllers;

import org.springframework.http.HttpRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClient.RequestHeadersSpec.ConvertibleClientHttpResponse;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/documents")
public class DocumentRelayController
{
    private final RestClient docsApiClient;

    public DocumentRelayController(RestClient docsApiClient)
    {
        this.docsApiClient = docsApiClient;
    }

    @GetMapping("/{documentId}")
    public ResponseEntity<String> getDocument(@PathVariable Long documentId)
    {
        return docsApiClient.get()
                .uri("/documents/{id}", documentId)
                .exchange(this:: relay);
    }

    @GetMapping
    public ResponseEntity<String> getAllDocuments()
    {
        return docsApiClient.get()
                .uri("/documents")
                .exchange(this:: relay);
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> createDocument(@RequestBody String body)
    {
        return docsApiClient.post()
                .uri("/documents")
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .exchange(this:: relay);
    }

    @PutMapping(value = "/{documentId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> updateDocument(@PathVariable Long documentId, @RequestBody String body)
    {
        return docsApiClient.put()
                .uri("/documents/{documentId}", documentId)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .exchange(this:: relay);
    }

    @DeleteMapping("/{documentId}")
    public ResponseEntity<String> deleteDocument(@PathVariable Long documentId)
    {
        return docsApiClient.delete()
                .uri("/documents/{documentId}", documentId)
                .exchange(this:: relay);
    }

    @PostMapping(value = "/{documentId}/shares", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> shareDocumentWithUser(@PathVariable Long documentId, @RequestBody String body)
    {
        return docsApiClient.post()
                .uri("/documents/{documentId}/shares", documentId)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .exchange(this:: relay);
    }

    // INTENTIONAL ATTACK SURFACE FOR PROVING CSRF DEMO
    // Accepts a plain HTML form so evil.html can reach it. Everything else in the API is JSON-only.
    @PostMapping(value = "/quick", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<String> quickCreateDocument(@RequestParam String title, @RequestParam String content)
    {
        return docsApiClient.post()
                .uri("/documents")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("title", title, "content", content))
                .exchange(this::relay);
    }

    private ResponseEntity<String> relay(HttpRequest request,
                                         ConvertibleClientHttpResponse response) throws IOException
    {
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(response.getStatusCode());
        MediaType contentType = response.getHeaders().getContentType();
        if (contentType != null) builder.contentType(contentType);
        return builder.body(response.bodyTo(String.class));
    }
}
