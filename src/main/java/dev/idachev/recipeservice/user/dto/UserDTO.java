package dev.idachev.recipeservice.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {
    private String username;
    private String email;
    private boolean verified;
    private boolean verificationPending;
    private LocalDateTime lastLogin;
} 