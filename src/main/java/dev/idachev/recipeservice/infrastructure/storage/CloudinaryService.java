package dev.idachev.recipeservice.infrastructure.storage;

import com.cloudinary.Cloudinary;
import dev.idachev.recipeservice.exception.ImageProcessingException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

/**
 * Service for handling image uploads to Cloudinary
 */
@Service
@Slf4j
public class CloudinaryService {

    private static final String RECIPE_IMAGES_FOLDER = "recipe-images";
    private static final String GENERATED_RECIPE_IMAGES_FOLDER = "generated-recipe-images";
    private static final String RESOURCE_TYPE = "auto";

    private final Cloudinary cloudinary;

    @Autowired
    public CloudinaryService(Cloudinary cloudinary) {
        this.cloudinary = cloudinary;
    }

    /**
     * Uploads an image from a URL to Cloudinary
     */
    public String uploadImageFromUrl(String imageUrl) {

        if (imageUrl == null || imageUrl.trim().isEmpty()) {

            throw new ImageProcessingException("Image URL is empty");
        }

        log.debug("Uploading image from URL: {}", imageUrl);
        String uniqueFilename = generateUniqueFilename();

        Map<String, Object> options = Map.of(
                "folder", GENERATED_RECIPE_IMAGES_FOLDER,
                "resource_type", RESOURCE_TYPE,
                "public_id", uniqueFilename
        );

        try {

            return processUpload(imageUrl, options);
        } catch (IOException e) {

            log.error("Failed to upload image from URL: {}", imageUrl, e);
            throw new ImageProcessingException("Failed to upload image from URL", e);
        }
    }

    /**
     * Processes the upload to Cloudinary
     */
    private String processUpload(Object input, Map<String, Object> options) throws IOException {
        @SuppressWarnings("unchecked")
        Map<String, Object> uploadResult = cloudinary.uploader().upload(input, options);

        String secureUrl = (String) uploadResult.get("secure_url");
        if (secureUrl == null) {
            throw new ImageProcessingException("Image upload failed, secure URL is missing");
        }

        log.debug("Image uploaded successfully: {}", secureUrl);
        return secureUrl;
    }

    /**
     * Generates a unique filename for an image
     */
    private String generateUniqueFilename() {
        return String.valueOf(UUID.randomUUID());
    }
} 