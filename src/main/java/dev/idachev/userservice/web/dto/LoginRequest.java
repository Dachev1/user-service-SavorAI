package dev.idachev.userservice.web.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for login requests
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Login request parameters")
public class LoginRequest {
    
    @NotBlank(message = "Username or email cannot be empty")
    @Size(max = 100, message = "Username or email must not exceed 100 characters")
    @Schema(description = "User's email address or username", example = "john.doe@example.com or johndoe")
    @JsonAlias("email") // Support legacy frontend requests still using "email" field
    private String identifier;
    
    @NotBlank(message = "Password cannot be empty")
    @Schema(description = "User's password", example = "password123")
    private String password;
    
    /**
     * Getter for email that delegates to identifier
     * For backward compatibility with code expecting the email field
     */
    @JsonIgnore
    public String getEmail() {
        return identifier;
    }
    
    /**
     * Setter for email that delegates to identifier
     * For backward compatibility with code expecting the email field
     */
    public void setEmail(String email) {
        this.identifier = email;
    }
} 