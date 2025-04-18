package dev.idachev.userservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Request payload for user sign-in.
 */
@Schema(description = "Request payload for user sign-in")
public record SignInRequest(
    
    @Schema(description = "User identifier (username or email)", requiredMode = Schema.RequiredMode.REQUIRED, example = "johndoe")
    @NotBlank(message = "Identifier cannot be blank")
    String identifier,
    
    @Schema(description = "User password", requiredMode = Schema.RequiredMode.REQUIRED, example = "Password123!")
    @NotBlank(message = "Password cannot be blank")
    String password
) {} 