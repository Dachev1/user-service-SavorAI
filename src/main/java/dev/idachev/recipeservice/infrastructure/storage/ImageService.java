package dev.idachev.recipeservice.infrastructure.storage;

import dev.idachev.recipeservice.exception.ImageProcessingException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.UUID;

/**
 * Infrastructure service for image storage operations.
 */
@Service
@Slf4j
public class ImageService {

    /**
     * Upload an image file and return its URL.
     */
    public String uploadImage(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            log.warn("Attempted to upload null or empty file");
            return null;
        }

        try {
            String uniqueFilename = generateUniqueFilename(file);
            log.info("Uploading image: {} (size: {} bytes)", file.getOriginalFilename(), file.getSize());

            // Placeholder for actual upload implementation
            return "https://example.com/images/" + uniqueFilename;
        } catch (Exception e) {
            log.error("Error uploading image: {}", e.getMessage());
            throw new ImageProcessingException("Failed to upload image", e);
        }
    }

    /**
     * Generate a unique filename
     */
    private String generateUniqueFilename(MultipartFile file) {
        String extension = "";
        String originalFilename = file.getOriginalFilename();

        if (originalFilename != null && originalFilename.contains(".")) {
            extension = originalFilename.substring(originalFilename.lastIndexOf("."));
        }

        return UUID.randomUUID() + extension;
    }
} 