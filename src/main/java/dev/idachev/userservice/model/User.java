package dev.idachev.userservice.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;


@Entity
@Table(name = "users", 
    indexes = {
        @Index(name = "idx_user_username", columnList = "username"),
        @Index(name = "idx_user_email", columnList = "email"),
        @Index(name = "idx_user_verification_token", columnList = "verificationToken")
    })
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder(toBuilder = true)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false, length = 50)
    private String username;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = false;

    @Column
    private String verificationToken;

    @Column(nullable = false, updatable = false)
    @CreationTimestamp
    private LocalDateTime createdOn;

    @Column(nullable = false)
    @UpdateTimestamp
    private LocalDateTime updatedOn;

    @Column
    private LocalDateTime lastLogin;

    @Column
    @Builder.Default
    private boolean loggedIn = false;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private Role role = Role.USER;

    @Column(nullable = false)
    @Builder.Default
    private boolean banned = false;

    public boolean isVerificationPending() {
        return verificationToken != null && !verificationToken.isEmpty();
    }

    public void enableAccount() {
        this.enabled = true;
        this.verificationToken = null;
    }

    public void disableAccount() {
        this.enabled = false;
    }

    public void updateVerificationToken(String token) {
        this.verificationToken = token;
    }

    public void updateLastLogin() {
        this.lastLogin = LocalDateTime.now();
    }

    public void markAsLoggedIn() {
        this.loggedIn = true;
    }

    public void markAsLoggedOut() {
        this.loggedIn = false;
    }

    public void changePassword(String newEncodedPassword) {
        this.password = newEncodedPassword;
    }

    public void updateRole(Role newRole) {
        this.role = newRole;
    }

    public void ban() {
        this.banned = true;
    }

    public void unban() {
        this.banned = false;
    }

    public void clearVerificationToken() {
        this.verificationToken = null;
    }

    public void updateUsername(String newUsername) {
        // Consider adding validation logic here if needed (e.g., format)
        // Uniqueness validation should happen in the service layer before calling this
        this.username = newUsername;
    }
} 