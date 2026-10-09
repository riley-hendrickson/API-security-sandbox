package apisecurity.docsapi.repositories;

import apisecurity.docsapi.entities.Document;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface DocumentRepository extends Repository<Document, Long>
{
    @Query("SELECT d FROM Document d WHERE d.id = :id AND (d.ownerId = :userId OR :userId MEMBER OF d.sharedWith)")
    Optional<Document> findById(@Param("id") Long id, @Param("userId") String userId);

    @Query("SELECT d FROM Document d WHERE d.ownerId = :userId OR :userId MEMBER OF d.sharedWith")
    List<Document> findAllVisibleTo(@Param("userId") String userId);

    @Query("SELECT d FROM Document d")
    List<Document> findAllForAdmin();

    Document save(Document document);

    void delete(Document document);
}
