package dev.idachev.userservice.validation;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

import java.lang.annotation.*;

/**
 * Custom validation annotation for complex password validation
 */
@Documented
@Constraint(validatedBy = PasswordValidator.PasswordConstraintValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface PasswordValidator {

    String message() default "Invalid password: must be at least 8 characters with at least one uppercase letter, one lowercase letter, one digit, and one special character";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    /**
     * Custom validator implementation for password validation
     */
    class PasswordConstraintValidator implements ConstraintValidator<PasswordValidator, String> {

        @Override
        public void initialize(PasswordValidator constraintAnnotation) {
            // No initialization needed
        }

        @Override
        public boolean isValid(String password, ConstraintValidatorContext context) {
            if (password == null) {
                return false;
            }

            // Minimum length check
            if (password.length() < 8) {
                return false;
            }

            // Check for at least one uppercase letter
            if (!password.matches(".*[A-Z].*")) {
                return false;
            }

            // Check for at least one lowercase letter
            if (!password.matches(".*[a-z].*")) {
                return false;
            }

            // Check for at least one digit
            if (!password.matches(".*\\d.*")) {
                return false;
            }

            // Check for at least one special character
            return password.matches(".*[^a-zA-Z0-9].*");
        }
    }
} 