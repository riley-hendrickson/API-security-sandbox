package apisecurity.docsapi;

import apisecurity.docsapi.entities.Document;
import apisecurity.docsapi.repositories.DocumentRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class SeedData implements CommandLineRunner
{
    private static final String ALICE = "11111111-1111-1111-1111-111111111111";
    private static final String BOB = "22222222-2222-2222-2222-222222222222";

    private final DocumentRepository repo;

    public SeedData(DocumentRepository repo)
    {
        this.repo = repo;
    }

    @Override
    public void run(String... args)
    {
        repo.save(new Document(ALICE, Set.of(), "Alice's private notes", ""));
        repo.save(new Document(BOB, Set.of(), "Bob's private notes", ""));
        repo.save(new Document(ALICE, Set.of(BOB), "Alice's shared notes with Bob", ""));
    }
}
