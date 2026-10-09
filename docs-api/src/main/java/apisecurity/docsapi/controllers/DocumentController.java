package apisecurity.docsapi.controllers;

import apisecurity.docsapi.dtos.CreateDocumentRequest;
import apisecurity.docsapi.dtos.DocumentResponse;
import apisecurity.docsapi.dtos.ShareRequest;
import apisecurity.docsapi.dtos.UpdateDocumentRequest;
import apisecurity.docsapi.exceptions.DocumentNotFoundException;
import apisecurity.docsapi.services.DocumentService;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
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
        DocumentResponse document;
        try
        {
            document = documentService.getDocument(authentication.name(), documentId);
        }
        catch(DocumentNotFoundException e)
        {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }

        return ResponseEntity.ok(document);
    }

    @GetMapping("/documents")
    public ResponseEntity<List<DocumentResponse>> getAllDocumentsForUser(Authentication authentication)
    {
        return ResponseEntity.ok(documentService.getAllDocumentsForUser(authentication.name()));
    }

    @GetMapping("/admin/documents")
    public ResponseEntity<List<DocumentResponse>> getAllDocumentsForAdmin()
    {
        return ResponseEntity.ok(documentService.getAllDocumentsForAdmin());
    }

    @PostMapping("/documents")
    public ResponseEntity<DocumentResponse> createDocument(Authentication authentication, @RequestBody CreateDocumentRequest request)
    {
        return ResponseEntity.ok(documentService.createDocument(authentication.name(), request));
    }

    @PutMapping("/documents")
    public ResponseEntity<Void> updateDocument(Authentication authentication, @RequestBody UpdateDocumentRequest request)
    {
        try
        {
            documentService.updateDocument(authentication.name(), request);
        }
        catch(DocumentNotFoundException e)
        {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("documents/{documentId}")
    public ResponseEntity<Void> deleteDocument(Authentication authentication, @PathVariable Long documentId)
    {
        try
        {
            documentService.deleteDocument(authentication.name(), documentId);
        }
        catch (DocumentNotFoundException e)
        {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        return ResponseEntity.ok().build();
    }

    @PostMapping("/documents/shared")
    public ResponseEntity<Void> shareDocumentWithUser(Authentication authentication, @RequestBody ShareRequest request)
    {
        try
        {
            documentService.shareDocument(authentication.name(), request);
        }
        catch (DocumentNotFoundException e)
        {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        return ResponseEntity.ok().build();
    }
}
