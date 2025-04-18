package dev.idachev.userservice.web;

import dev.idachev.userservice.service.EmailService;
import dev.idachev.userservice.util.ResponseBuilder;
import dev.idachev.userservice.web.dto.ContactFormRequest;
import dev.idachev.userservice.web.dto.GenericResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for handling contact form submissions
 */
@Slf4j
@RestController
@CrossOrigin(origins = "*", maxAge = 3600)
@RequestMapping("/api/v1/contact")
@Tag(name = "Contact", description = "Endpoint for submitting contact inquiries")
@RequiredArgsConstructor
public class ContactController {

    private final EmailService emailService;
    
    /**
     * Endpoint for submitting a contact form.
     * The email sending is performed synchronously/asynchronously based on EmailService configuration.
     *
     * @param request The contact form request
     * @return Response indicating acceptance of the request
     */
    @PostMapping("/submit")
    @Operation(
            summary = "Submit contact form",
            description = "Sends a contact form submission via email to the configured recipient."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Message submission accepted. Actual email delivery depends on the mail server.",
                    content = @Content(schema = @Schema(implementation = GenericResponse.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid input data (validation errors on request body)"
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error (e.g., failed to send email)"
            )
    })
    public ResponseEntity<GenericResponse> submitContactForm(
            @Valid @RequestBody ContactFormRequest request
    ) {
        log.info("Received contact form submission from: {}, subject: {}", request.getEmail(), request.getSubject());
        
        emailService.sendContactFormEmail(
                request.getEmail(),
                request.getSubject(),
                request.getMessage()
        );
        
        log.info("Contact form submitted for processing from: {}", request.getEmail());
        
        return ResponseEntity.ok(ResponseBuilder.success(
                "Thank you for your message. We will get back to you soon."));
    }
} 