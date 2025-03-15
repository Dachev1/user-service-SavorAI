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

    private boolean enabled;

    @Column
    private String verificationToken;

    @Column
    private LocalDateTime createdOn = LocalDateTime.now();
    
    @Column
    private LocalDateTime updatedOn = LocalDateTime.now();
    
    @Column
    private LocalDateTime lastLogin;

    @Column
    private boolean loggedIn = false;

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

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

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        this.updatedOn = LocalDateTime.now();
    }

    public void setUsername(String username) {
        this.username = username;
        this.updatedOn = LocalDateTime.now();
    }

    public void setEmail(String email) {
        this.email = email;
        this.updatedOn = LocalDateTime.now();
    }

    public void setPassword(String password) {
        this.password = password;
        this.updatedOn = LocalDateTime.now();
    }

    public void setVerificationToken(String verificationToken) {
        this.verificationToken = verificationToken;
        this.updatedOn = LocalDateTime.now();
    }

    public void setLoggedIn(boolean loggedIn) {
        this.loggedIn = loggedIn;
        this.updatedOn = LocalDateTime.now();
    }

    public void updateLastLogin() {
        this.lastLogin = LocalDateTime.now();
        this.updatedOn = LocalDateTime.now();
    }

    public boolean isVerificationPending() {
        return verificationToken != null && !verificationToken.isEmpty();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
    }
    
    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", enabled=" + enabled +
                ", verificationPending=" + isVerificationPending() +
                ", loggedIn=" + loggedIn +
                ", lastLogin=" + lastLogin +
                '}';
    }
} 