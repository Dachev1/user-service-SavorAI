package dev.idachev.userservice.web.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

/**
 * Response DTO for email verification and other verification operations.
 * Contains information about the success/failure of the verification operation
 * and additional details that might be useful to the client.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Response for email verification operations")
public class VerificationResponse {

    /**
     * Indicates whether the verification was successful
     */
    @Schema(description = "Whether the verification was successful", example = "true")
    private boolean success;

    /**
     * A message describing the result of the verification
     */
    @Schema(description = "Message describing the verification result", example = "Your email has been verified successfully")
    private String message;

    /**
     * Timestamp of when the verification was processed
     */
    @NotNull(message = "Timestamp cannot be null")
    @Schema(description = "Timestamp when verification was processed")
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();

    /**
     * Optional field for additional data that might be needed by the client
     */
    @Valid
    @Schema(description = "Additional data about the verification (may be null)")
    private Object data;

    /**
     * Optional redirection URL that the client can use after verification
     */
    @Schema(description = "Optional redirection URL for the client", example = "http://example.com/login")
    private String redirectUrl;

    /**
     * Creates a success response with a message
     *
     * @param message Success message
     * @return VerificationResponse with success=true
     */
    public static VerificationResponse success(String message) {
        return VerificationResponse.builder()
                .success(true)
                .message(message)
                .build();
    }

    /**
     * Creates a failure response with a message
     *
     * @param message Error message
     * @return VerificationResponse with success=false
     */
    public static VerificationResponse failure(String message) {
        return VerificationResponse.builder()
                .success(false)
                .message(message)
                .build();
    }
} 