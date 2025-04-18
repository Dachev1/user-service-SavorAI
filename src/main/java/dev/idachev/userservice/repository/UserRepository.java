package dev.idachev.userservice.repository;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.stereotype.Repository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import java.time.LocalDateTime;
import java.util.List;

import jakarta.persistence.QueryHint;
import static org.hibernate.jpa.HibernateHints.HINT_CACHEABLE;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.repository.query.Param;

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
    
    @Query("SELECT u.username FROM User u WHERE u.id = :userId")
    Optional<String> findUsernameById(@Param("userId") UUID userId);
    
    @QueryHints(@QueryHint(name = HINT_CACHEABLE, value = "true"))
    long countByBannedTrue();
    
    @QueryHints(@QueryHint(name = HINT_CACHEABLE, value = "true"))
    long countByBannedFalse();
    
    @QueryHints(@QueryHint(name = HINT_CACHEABLE, value = "true"))
    long countByEnabledTrue();
    
    @QueryHints(@QueryHint(name = HINT_CACHEABLE, value = "true"))
    long countByRole(Role role);

    @Query("SELECT u FROM User u WHERE u.createdOn > ?1")
    List<User> findByCreatedOnAfter(LocalDateTime createdOn);
} 
