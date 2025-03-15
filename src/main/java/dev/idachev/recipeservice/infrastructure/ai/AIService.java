package dev.idachev.recipeservice.infrastructure.ai;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.recipeservice.exception.AIServiceException;
import dev.idachev.recipeservice.exception.ValidationException;
import dev.idachev.recipeservice.infrastructure.storage.CloudinaryService;
import dev.idachev.recipeservice.mapper.AIServiceMapper;
import dev.idachev.recipeservice.web.dto.RecipeRequest;
import dev.idachev.recipeservice.web.dto.SimplifiedRecipeResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.ChatClient;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.image.ImageClient;
import org.springframework.ai.image.ImagePrompt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.UUID;

/**
 * AI recipe generation service using Spring AI's OpenAI integration
 */
@Service
@Slf4j
@Tag(name = "AI Service", description = "Provides AI-powered recipe generation functionality")
public class AIService {

    // Constants for parameter limits
    private static final int MAX_INGREDIENTS = 20;
    private static final int UUID_LENGTH = 8;

    private final ChatClient chatClient;
    private final ImageClient imageClient;
    private final ObjectMapper objectMapper;
    private final CloudinaryService cloudinaryService;

    @Autowired
    public AIService(ChatClient chatClient, ImageClient imageClient, ObjectMapper objectMapper, CloudinaryService cloudinaryService) {
        this.chatClient = chatClient;
        this.imageClient = imageClient;
        this.objectMapper = objectMapper;
        this.cloudinaryService = cloudinaryService;
    }

    /**
     * Generate a unique recipe from ingredients
     *
     * @param ingredients List of ingredients to use
     * @return Recipe with details and image URL
     */
    @Operation(summary = "Generate a recipe from ingredients")
    public SimplifiedRecipeResponse generateRecipeFromIngredients(List<String> ingredients) {

        if (ingredients == null || ingredients.isEmpty()) {

            throw new ValidationException("Ingredients list cannot be empty");
        }

        // Limit ingredients for API efficiency
        if (ingredients.size() > MAX_INGREDIENTS) {

            log.warn("Too many ingredients ({}). Limiting to first {}", ingredients.size(), MAX_INGREDIENTS);

            ingredients = ingredients.subList(0, MAX_INGREDIENTS);
        }

        log.info("Generating recipe from {} ingredients", ingredients.size());

        try {
            RecipeRequest recipeRequest = generateRecipeRequestFromAI(ingredients);

            String imageUrl = generateRecipeImage(recipeRequest.getTitle(), recipeRequest.getDescription());
            SimplifiedRecipeResponse result = AIServiceMapper.toSimplifiedResponse(recipeRequest, imageUrl);

            log.info("Generated recipe: {}", result.getTitle());
            return result;
        } catch (JsonProcessingException e) {

            log.error("Error parsing AI response: {}", e.getMessage());
            throw new AIServiceException("Failed to parse AI-generated recipe", e);
        } catch (Exception e) {

            log.error("Error generating recipe: {}", e.getMessage());
            throw new AIServiceException("Failed to generate recipe", e);
        }
    }

    /**
     * Generate recipe using AI
     */
    private RecipeRequest generateRecipeRequestFromAI(List<String> ingredients) throws JsonProcessingException {

        Message systemMessage = new SystemMessage(RecipePrompts.getRecipeFromIngredientsPrompt());
        String uniquePrompt = createUniquePrompt(ingredients);
        Message userMessage = new UserMessage(uniquePrompt);

        String content = chatClient.call(new Prompt(List.of(systemMessage, userMessage)))
                .getResult().getOutput().getContent();

        if (!StringUtils.hasText(content)) {

            throw new AIServiceException("AI returned empty response", null);
        }

        return objectMapper.readValue(content, RecipeRequest.class);
    }

    /**
     * Create unique prompt for recipe generation
     */
    private String createUniquePrompt(List<String> ingredients) {

        String uniqueId = UUID.randomUUID().toString().substring(0, UUID_LENGTH);
        String joinedIngredients = String.join(", ", ingredients);

        return RecipePrompts.getUniqueRecipePrompt(joinedIngredients, uniqueId);
    }

    /**
     * Generate recipe image and store in Cloudinary
     * Designed to fail gracefully and return null rather than throw exceptions
     */
    @Operation(summary = "Generate an image for a recipe")
    public String generateRecipeImage(String recipeTitle, String recipeDescription) {

        if (!StringUtils.hasText(recipeTitle)) {
            log.warn("Recipe title empty, cannot generate image");
            return null;
        }

        try {

            String promptText = RecipePrompts.getRecipeImagePrompt(recipeTitle, recipeDescription);
            String imageUrl = imageClient.call(new ImagePrompt(promptText))
                    .getResult().getOutput().getUrl();

            if (!StringUtils.hasText(imageUrl)) {

                log.warn("AI returned empty image URL for recipe: {}", recipeTitle);
                return null;
            }

            // Upload to Cloudinary for permanent storage
            try {
                String cloudinaryUrl = cloudinaryService.uploadImageFromUrl(imageUrl);

                if (cloudinaryUrl == null) {

                    throw new AIServiceException("Cloudinary returned null URL", null);
                }
                return cloudinaryUrl;
            } catch (Exception e) {

                log.error("Error uploading to Cloudinary: {}", e.getMessage());
                // Fallback to original URL instead of returning null
                return imageUrl;
            }
        } catch (Exception e) {

            log.error("Error generating recipe image: {}", e.getMessage());
            return null;
        }
    }
} 