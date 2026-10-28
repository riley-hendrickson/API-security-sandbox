package apisecurity.docsapi.controllers;

import apisecurity.docsapi.services.DocumentService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/reports")
public class InternalReportsController
{
    private final DocumentService documentService;

    public InternalReportsController(DocumentService documentService)
    {
        this.documentService = documentService;
    }

    @GetMapping("/summary")
    public ResponseEntity<String> getSummary(Authentication authentication)
    {
        return ResponseEntity.ok().body(documentService.getDocumentCountForSystem() + " documents currently in the system. " + authentication.getName());
    }
}
