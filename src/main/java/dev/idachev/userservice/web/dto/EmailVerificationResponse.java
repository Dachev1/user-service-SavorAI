package dev.idachev.userservice.web.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class EmailVerificationResponse {
    private boolean success;
    private String message;
    private LocalDateTime timestamp;
} 