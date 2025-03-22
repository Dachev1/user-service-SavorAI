package dev.idachev.userservice.web;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping("/test/not-found")
    public String notFound() {
        throw new ResourceNotFoundException("Resource not found");
    }

    @GetMapping("/test/bad-credentials")
    public String badCredentials() {
        throw new BadCredentialsException("Invalid credentials");
    }

    @GetMapping("/test/already-logged-in")
    public String alreadyLoggedIn() {
        throw new AuthenticationException("You are already logged in");
    }

    @GetMapping("/test/duplicate-user")
    public String duplicateUser() {
        throw new DuplicateUserException("User already exists");
    }

    @GetMapping("/test/bad-request")
    public String badRequest() {
        throw new IllegalArgumentException("Invalid request parameters");
    }

    @GetMapping("/test/server-error")
    public String serverError() {
        throw new RuntimeException("Unexpected server error");
    }
} 