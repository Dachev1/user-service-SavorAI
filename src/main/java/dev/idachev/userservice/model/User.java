package dev.idachev.userservice.model;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.UUID;

/**
 * User entity representing application users.
 * Implements UserDetails for Spring Security integration.
 */
@Entity
@Table
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false, length = 50)
    private String username;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column
    private boolean enabled;

    @Column
    private String verificationToken;

    @Column
    @Builder.Default
    private LocalDateTime createdOn = LocalDateTime.now();

    @Column
    @Builder.Default
    private LocalDateTime updatedOn = LocalDateTime.now();

    @Column
    private LocalDateTime lastLogin;

    @Column
    @Builder.Default
    private boolean loggedIn = false;


    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedOn = LocalDateTime.now();
    }

    public void updateLastLogin() {
        this.lastLogin = LocalDateTime.now();
    }

    public boolean isVerificationPending() {
        return verificationToken != null && !verificationToken.isEmpty();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
    }
} 