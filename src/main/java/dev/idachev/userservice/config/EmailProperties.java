package dev.idachev.userservice.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Email;

@Getter
@Setter
@Validated
@Configuration
@ConfigurationProperties(prefix = "email-service-config")
public class EmailProperties {

    /**
     * The application name displayed in emails.
     */
    @NotBlank(message = "Application name cannot be blank")
    private String appName = "My Application"; // Provide a default or configure in properties

    /**
     * The 'From' address for outgoing emails.
     */
    @NotBlank(message = "'From' address cannot be blank")
    @Email(message = "Invalid 'From' email address format")
    private String fromAddress;

    /**
     * The default recipient for contact form submissions.
     */
    @NotBlank(message = "Contact recipient email cannot be blank")
    @Email(message = "Invalid contact recipient email address format")
    private String contactRecipient;

    /**
     * The base URL of the service, used for constructing links in emails (e.g., verification links).
     * Example: https://yourapp.com
     */
    @NotBlank(message = "Service base URL cannot be blank")
    private String serviceBaseUrl;

    // Optional: Add other email-related properties like host, port, auth details if not using Spring Boot autoconfiguration
    // private String host;
    // private int port;
    // private String username;
    // private String password;

} 