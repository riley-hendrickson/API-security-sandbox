package apisecurity.docsapi.entities;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "documents")
@Getter
@NoArgsConstructor(access= AccessLevel.PROTECTED)
public class Document
{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false)
    private String ownerId;
    @Setter
    @ElementCollection
    @CollectionTable(name = "document_shares", joinColumns = @JoinColumn(name = "document_id"))
    @Column(name = "user_id")
    private Set<String> sharedWith;
    @Setter
    private String title;
    @Setter
    @Column(length = 10000)
    private String contents;

    public Document(String ownerId, Set<String> sharedWith, String title, String contents)
    {
        this.ownerId = ownerId;
        this.sharedWith = new HashSet<>(sharedWith);
        this.title = title;
        this.contents = contents;
    }
}
