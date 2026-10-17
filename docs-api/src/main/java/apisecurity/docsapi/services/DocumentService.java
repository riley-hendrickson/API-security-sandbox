package apisecurity.docsapi.services;

import apisecurity.docsapi.dtos.CreateDocumentRequest;
import apisecurity.docsapi.dtos.DocumentResponse;
import apisecurity.docsapi.dtos.ShareRequest;
import apisecurity.docsapi.dtos.UpdateDocumentRequest;
import apisecurity.docsapi.entities.Document;
import apisecurity.docsapi.enums.AuditAction;
import apisecurity.docsapi.events.DocumentChangedEvent;
import apisecurity.docsapi.exceptions.DocumentNotFoundException;
import apisecurity.docsapi.exceptions.ForbiddenOperationException;
import apisecurity.docsapi.repositories.DocumentRepository;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class DocumentService
{
    private final DocumentRepository documentRepository;
    private final ApplicationEventPublisher events;

    public DocumentService(DocumentRepository documentRepository, ApplicationEventPublisher events)
    {
        this.documentRepository = documentRepository;
        this.events = events;
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
        Document saved = documentRepository.save(newDocument);
        events.publishEvent(new DocumentChangedEvent(AuditAction.DOCUMENT_CREATED, saved.getId()));
        return convertToResponse(saved);
    }

    @Transactional
    public void updateDocument(String userId, Long documentId, UpdateDocumentRequest request) throws DocumentNotFoundException
    {
        Optional<Document> storedDocument = documentRepository.findById(documentId, userId);
        if (storedDocument.isEmpty()) throw new DocumentNotFoundException("Document not found");

        Document updatedDocument = storedDocument.get();
        updatedDocument.setTitle(request.title());
        updatedDocument.setContents(request.content());
        documentRepository.save(updatedDocument);
        events.publishEvent(new DocumentChangedEvent(AuditAction.DOCUMENT_UPDATED, documentId));
    }

    @Transactional
    public void deleteDocument(String userId, Long documentId) throws DocumentNotFoundException, ForbiddenOperationException
    {
        Optional<Document> storedDocument = documentRepository.findById(documentId, userId);
        if (storedDocument.isEmpty()) throw new DocumentNotFoundException("Document not found");
        if (!storedDocument.get().getOwnerId().equals(userId))
            throw new ForbiddenOperationException("Only the owner can delete a document");
        documentRepository.delete(storedDocument.get());
        events.publishEvent(new DocumentChangedEvent(AuditAction.DOCUMENT_DELETED, documentId));
    }

    @Transactional
    public void shareDocument(String userId, Long documentId, ShareRequest request) throws DocumentNotFoundException, ForbiddenOperationException
    {
        Optional<Document> storedDocument = documentRepository.findById(documentId, userId);
        if (storedDocument.isEmpty())
            throw new DocumentNotFoundException("Document not found");
        if(!storedDocument.get().getOwnerId().equals(userId)) throw new ForbiddenOperationException("Only the owner can share a document");
        Document document = storedDocument.get();
        document.getSharedWith().addAll(request.userIds());
        documentRepository.save(document);
        events.publishEvent(new DocumentChangedEvent(AuditAction.DOCUMENT_SHARED, documentId));
    }

    private DocumentResponse convertToResponse(Document document)
    {
        return new DocumentResponse(document.getId(), document.getOwnerId(), Set.copyOf(document.getSharedWith()), document.getTitle(), document.getContents());
    }
}
