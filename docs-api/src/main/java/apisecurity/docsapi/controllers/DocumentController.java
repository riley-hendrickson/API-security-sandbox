package apisecurity.docsapi.controllers;

import apisecurity.docsapi.dtos.CreateDocumentRequest;
import apisecurity.docsapi.dtos.DocumentResponse;
import apisecurity.docsapi.dtos.ShareRequest;
import apisecurity.docsapi.dtos.UpdateDocumentRequest;
import apisecurity.docsapi.services.DocumentService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class DocumentController
{
    private final DocumentService documentService;

    public DocumentController(DocumentService documentService)
    {
        this.documentService = documentService;
    }

    @GetMapping("/documents/{documentId}")
    public ResponseEntity<DocumentResponse> getDocument(Authentication authentication, @PathVariable Long documentId)
    {
        return ResponseEntity.ok(documentService.getDocument(authentication.getName(), documentId));
    }

    @GetMapping("/documents")
    public ResponseEntity<List<DocumentResponse>> getAllDocumentsForUser(Authentication authentication)
    {
        return ResponseEntity.ok(documentService.getAllDocumentsForUser(authentication.getName()));
    }

    @GetMapping("/admin/documents")
    public ResponseEntity<List<DocumentResponse>> getAllDocumentsForAdmin()
    {
        return ResponseEntity.ok(documentService.getAllDocumentsForAdmin());
    }

    @PostMapping("/documents")
    public ResponseEntity<DocumentResponse> createDocument(Authentication authentication, @Valid @RequestBody CreateDocumentRequest request)
    {
        return ResponseEntity.status(HttpStatus.CREATED).body(documentService.createDocument(authentication.getName(), request));
    }

    @PutMapping("/documents/{documentId}")
    public ResponseEntity<Void> updateDocument(Authentication authentication, @PathVariable Long documentId, @Valid @RequestBody UpdateDocumentRequest request)
    {
        documentService.updateDocument(authentication.getName(), documentId, request);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/documents/{documentId}")
    public ResponseEntity<Void> deleteDocument(Authentication authentication, @PathVariable Long documentId)
    {
        documentService.deleteDocument(authentication.getName(), documentId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/documents/{documentId}/shares")
    public ResponseEntity<Void> shareDocumentWithUser(Authentication authentication, @PathVariable Long documentId, @Valid @RequestBody ShareRequest request)
    {
        documentService.shareDocument(authentication.getName(), documentId, request);
        return ResponseEntity.ok().build();
    }
}
