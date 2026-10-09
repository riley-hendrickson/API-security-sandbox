package apisecurity.docsapi.services;

import apisecurity.docsapi.dtos.CreateDocumentRequest;
import apisecurity.docsapi.dtos.DocumentResponse;
import apisecurity.docsapi.dtos.ShareRequest;
import apisecurity.docsapi.dtos.UpdateDocumentRequest;
import apisecurity.docsapi.entities.Document;
import apisecurity.docsapi.exceptions.DocumentNotFoundException;
import apisecurity.docsapi.repositories.DocumentRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;

@Service
public class DocumentService
{
    private final DocumentRepository documentRepository;

    public DocumentService(DocumentRepository documentRepository)
    {
        this.documentRepository = documentRepository;
    }

    @Transactional(readOnly = true)
    public DocumentResponse getDocument(String userId, Long documentId) throws DocumentNotFoundException
    {
        Optional<Document> document = documentRepository.findById(documentId, userId);
        return document.map(this::convertToResponse).orElseThrow(() -> new DocumentNotFoundException("Document not found"));
    }

    @Transactional(readOnly = true)
    public List<DocumentResponse> getAllDocumentsForUser(String userId)
    {
        return documentRepository.findAllVisibleTo(userId).stream()
                .map(this::convertToResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('ADMIN')")
    public List<DocumentResponse> getAllDocumentsForAdmin()
    {
        return documentRepository.findAllForAdmin().stream()
                .map(this::convertToResponse)
                .toList();
    }

    @Transactional
    public DocumentResponse createDocument(String userId, CreateDocumentRequest request)
    {
        Document newDocument = new Document(userId, new HashSet<>(), request.title(), request.content());
        return convertToResponse(documentRepository.save(newDocument));
    }

    @Transactional
    public void updateDocument(String userId, UpdateDocumentRequest request) throws DocumentNotFoundException
    {
        Optional<Document> storedDocument = documentRepository.findById(request.id(), userId);
        if (storedDocument.isEmpty()) throw new DocumentNotFoundException("Document not found");

        Document updatedDocument = storedDocument.get();
        updatedDocument.setTitle(request.title());
        updatedDocument.setContents(request.content());
        documentRepository.save(updatedDocument);
    }

    @Transactional
    public void deleteDocument(String userId, Long documentId) throws DocumentNotFoundException
    {
        Optional<Document> storedDocument = documentRepository.findById(documentId, userId);
        if (storedDocument.isEmpty() || !storedDocument.get().getOwnerId().equals(userId)) throw new DocumentNotFoundException("Document not found");
        documentRepository.delete(storedDocument.get());
    }

    @Transactional
    public void shareDocument(String userId, ShareRequest request) throws DocumentNotFoundException
    {
        Optional<Document> storedDocument = documentRepository.findById(request.documentId(), userId);
        if (storedDocument.isEmpty() || !storedDocument.get().getOwnerId().equals(userId))
            throw new DocumentNotFoundException("Document not found");
        Document document = storedDocument.get();
        document.getSharedWith().addAll(request.userIds());
        documentRepository.save(document);
    }

    private DocumentResponse convertToResponse(Document document)
    {
        return new DocumentResponse(document.getId(), document.getOwnerId(), document.getSharedWith(), document.getTitle(), document.getContents());
    }
}
