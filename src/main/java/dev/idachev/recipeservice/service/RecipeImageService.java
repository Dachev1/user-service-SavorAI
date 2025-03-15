package dev.idachev.recipeservice.service;

import dev.idachev.recipeservice.exception.ImageProcessingException;
import dev.idachev.recipeservice.infrastructure.ai.AIService;
import dev.idachev.recipeservice.infrastructure.storage.ImageService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

/**
 * Service for recipe image operations.
 * Handles uploading and generating images for recipes.
 */
@Service
@Slf4j
public class RecipeImageService {

    private final AIService aiService;
    private final ImageService imageService;


    @Autowired
    public RecipeImageService(AIService aiService, ImageService imageService) {
        this.aiService = aiService;
        this.imageService = imageService;
    }


    /**
     * Process image for a recipe (upload or generate)
     * <p>
     * If a MultipartFile is provided, it will be uploaded.
     * If no image is provided but a title is available, an image will be generated.
     *
     * @param title       Recipe title, used for generating an image if none is uploaded
     * @param description Recipe description, used for generating an image
     * @param image       Optional image file to upload
     * @return URL of the processed image, or null if no image could be processed
     */
    public String processRecipeImage(String title, String description, MultipartFile image) {
        try {
            // If an image file is provided, upload it
            if (image != null && !image.isEmpty()) {
                log.debug("Uploading image for recipe: {}", title);

                String imageUrl = uploadRecipeImage(image);
                log.info("Image uploaded for recipe '{}': {}", title, imageUrl);

                return imageUrl;
            }

            // Otherwise, if title is available, generate an image
            if (StringUtils.hasText(title)) {

                log.debug("No image provided, will attempt to generate one for: {}", title);
                return generateRecipeImage(title, description);
            }

            log.debug("No image provided and no title available for image generation");
            return null;
        } catch (Exception e) {

            log.error("Failed to process recipe image: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Upload a recipe image
     *
     * @param image Image file to upload
     * @return URL of the uploaded image
     * @throws ImageProcessingException if upload fails
     */
    private String uploadRecipeImage(MultipartFile image) {

        try {

            return imageService.uploadImage(image);
        } catch (Exception e) {

            String errorMessage = "Failed to upload image: " + e.getMessage();
            log.error(errorMessage, e);
            throw new ImageProcessingException(errorMessage, e);
        }
    }

    /**
     * Generate image for a recipe using AI
     *
     * @param title       Recipe title, used as the primary prompt for generation
     * @param description Recipe description, used to enhance the prompt
     * @return URL of the generated image, or null if generation fails
     */
    public String generateRecipeImage(String title, String description) {

        if (!StringUtils.hasText(title)) {
            log.warn("Cannot generate image: Recipe title is empty");
            return null;
        }

        try {
            log.info("Requesting AI image generation for recipe: {}", title);
            String imageUrl = aiService.generateRecipeImage(title, description);

            if (!StringUtils.hasText(imageUrl)) {
                log.warn("AI service returned empty image URL for recipe: {}", title);
                return null;
            }

            log.info("Successfully generated image for recipe: {}", title);
            return imageUrl;
        } catch (Exception e) {
            log.error("Failed to generate image: {}", e.getMessage(), e);
            return null;
        }
    }
} 