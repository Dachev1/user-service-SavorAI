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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for handling contact form submissions
 */
@Slf4j
@RestController
@CrossOrigin(origins = "*", maxAge = 3600)
@RequestMapping("/api/v1/contact")
@Tag(name = "Contact")
public class ContactController {

    private final EmailService emailService;
    
    @Autowired
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
        
        GenericResponse response = emailService.processContactForm(
                request.getEmail(),
                request.getSubject(),
                request.getMessage()
        );
        
        log.info("Contact form processed successfully from: {}", request.getEmail());
        
        return ResponseEntity.status(response.getStatus())
                .body(response);
    }
} 