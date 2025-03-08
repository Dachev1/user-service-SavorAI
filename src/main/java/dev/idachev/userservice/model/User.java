package dev.idachev.userservice.model;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;

@Entity
@Table
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

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
    @Builder.Default
    private LocalDateTime createdOn = LocalDateTime.now();
    
    @Column
    @Builder.Default
    private LocalDateTime updatedOn = LocalDateTime.now();
    
    @Column
    private LocalDateTime lastLogin;

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

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
    }

    public void setPassword(String password) {
        this.password = password;
        this.updatedOn = LocalDateTime.now();
    }

    public void setVerificationToken(String verificationToken) {
        this.verificationToken = verificationToken;
        this.updatedOn = LocalDateTime.now();
    }
    
    /**
     * Updates the last login timestamp to the current time
     */
    public void updateLastLogin() {
        this.lastLogin = LocalDateTime.now();
    }
    
    /**
     * Checks if this user account has a pending email verification
     * @return true if verification is pending (token is not null), false otherwise
     */
    public boolean isVerificationPending() {
        return verificationToken != null;
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedOn = LocalDateTime.now();
    }
    
    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", enabled=" + enabled +
                ", verificationPending=" + isVerificationPending() +
                ", lastLogin=" + lastLogin +
                '}';
    }
} 