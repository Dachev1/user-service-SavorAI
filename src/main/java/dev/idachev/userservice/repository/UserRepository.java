package dev.idachev.userservice.repository;

import dev.idachev.userservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.stereotype.Repository;

import jakarta.persistence.QueryHint;
import static org.hibernate.jpa.HibernateHints.HINT_CACHEABLE;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    @QueryHints(@QueryHint(name = HINT_CACHEABLE, value = "true"))
    boolean existsByUsername(String username);

    @QueryHints(@QueryHint(name = HINT_CACHEABLE, value = "true"))
    boolean existsByEmail(String email);

    @QueryHints(@QueryHint(name = HINT_CACHEABLE, value = "true"))
    Optional<User> findByEmail(String email);

    @QueryHints(@QueryHint(name = HINT_CACHEABLE, value = "true"))
    Optional<User> findByUsername(String username);

    @QueryHints(@QueryHint(name = HINT_CACHEABLE, value = "true"))
    Optional<User> findByVerificationToken(String token);
    
    @Query("SELECT u.username FROM User u WHERE u.id = ?1")
    Optional<String> findUsernameById(UUID userId);
} 
