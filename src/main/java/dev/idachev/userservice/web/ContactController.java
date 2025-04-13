package dev.idachev.userservice.web;

import dev.idachev.userservice.service.EmailService;
import dev.idachev.userservice.web.dto.ContactFormRequest;
import dev.idachev.userservice.web.dto.GenericResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

/**
 * Controller for handling contact form submissions
 */
@Slf4j
@RestController
@CrossOrigin(origins = "*", maxAge = 3600)
@RequestMapping("/api/v1/contact")
@Tag(name = "Contact", description = "Contact form submission endpoints")
public class ContactController {

    private final EmailService emailService;

    public ContactController(EmailService emailService) {
        this.emailService = emailService;
    }

    /**
     * Endpoint for submitting a contact form
     *
     * @param request The contact form request
     * @return Response indicating success or failure
     */
    @PostMapping("/submit")
    @Operation(
            summary = "Submit contact form",
            description = "Send a contact form submission that will be emailed to the admin"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Message sent successfully"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid input data"
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error"
            )
    })
    public ResponseEntity<GenericResponse> submitContactForm(
            @Valid @RequestBody ContactFormRequest request
    ) {
        log.info("Received contact form submission from: {}, subject: {}", request.getEmail(), request.getSubject());
        
        try {
            // Send the contact form email asynchronously
            emailService.sendContactFormEmailAsync(
                    request.getEmail(),
                    request.getSubject(),
                    request.getMessage()
            );
            
            log.info("Contact form processed successfully from: {}", request.getEmail());
            
            return ResponseEntity.ok(GenericResponse.builder()
                    .status(HttpStatus.OK.value())
                    .message("Thank you for your message. We'll get back to you soon!")
                    .timestamp(LocalDateTime.now())
                    .success(true)
                    .build());
        } catch (Exception e) {
            log.error("Error processing contact form from {}: {}", request.getEmail(), e.getMessage(), e);
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(GenericResponse.builder()
                            .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                            .message("Failed to process your request. Please try again later.")
                            .timestamp(LocalDateTime.now())
                            .success(false)
                            .build());
        }
    }
} 