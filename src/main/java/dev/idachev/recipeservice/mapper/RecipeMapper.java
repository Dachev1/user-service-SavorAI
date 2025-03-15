package dev.idachev.recipeservice.mapper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.recipeservice.exception.ValidationException;
import dev.idachev.recipeservice.model.DifficultyLevel;
import dev.idachev.recipeservice.model.Macros;
import dev.idachev.recipeservice.model.Recipe;
import dev.idachev.recipeservice.web.dto.RecipeRequest;
import dev.idachev.recipeservice.web.dto.RecipeResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Mapper utility for recipe transformations.
 * Provides methods for converting between Recipe entities and DTOs.
 */
@Component
@Slf4j
public class RecipeMapper {

    private final ObjectMapper objectMapper;
    private static final String EMPTY_JSON_ARRAY = "[]";
    private static final TypeReference<List<String>> INGREDIENTS_TYPE = new TypeReference<>() {};

    @Autowired
    public RecipeMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        log.debug("ObjectMapper initialized in RecipeMapper");
    }

    /**
     * Converts a Recipe entity to a RecipeResponse DTO.
     *
     * @param recipe The Recipe entity to convert
     * @return The corresponding RecipeResponse DTO
     * @throws IllegalArgumentException if recipe is null
     */
    public RecipeResponse toResponse(Recipe recipe) {

        if (recipe == null) {
            throw new IllegalArgumentException("Cannot convert null recipe to RecipeResponse");
        }

        List<String> ingredientsList = parseIngredients(recipe.getIngredients());

        return RecipeResponse.builder()
                .id(recipe.getId())
                .title(recipe.getTitle())
                .description(recipe.getDescription())
                .instructions(recipe.getInstructions())
                .imageUrl(recipe.getImageUrl())
                .ingredients(ingredientsList)
                .createdById(recipe.getUserId())
                .createdAt(recipe.getCreatedAt())
                .updatedAt(recipe.getUpdatedAt())
                .totalTimeMinutes(recipe.getTotalTimeMinutes())
                .macros(recipe.getMacros() != null ? MacrosMapper.toDto(recipe.getMacros()) : null)
                .difficulty(toDifficultyLevel(recipe.getDifficulty()))
                .isAiGenerated(recipe.getIsAiGenerated())
                .isFavorite(false) // Default value, will be set by service
                .favoriteCount(0L) // Default value, will be set by service
                .build();
    }

    /**
     * Converts a RecipeRequest DTO to a Recipe entity.
     *
     * @param request The RecipeRequest DTO to convert
     * @return The corresponding Recipe entity
     * @throws IllegalArgumentException if request is null
     * @throws ValidationException      if JSON serialization fails
     */
    public Recipe toEntity(RecipeRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Cannot convert null request to Recipe entity");
        }

        Recipe recipe = new Recipe();
        recipe.setTitle(request.getTitle());
        recipe.setDescription(request.getDescription());
        recipe.setInstructions(request.getInstructions());
        recipe.setImageUrl(request.getImageUrl());
        recipe.setIngredients(serializeIngredients(request.getIngredients()));
        recipe.setTotalTimeMinutes(request.getTotalTimeMinutes());
        recipe.setDifficulty(request.getDifficulty() != null ? request.getDifficulty().name() : null);
        recipe.setIsAiGenerated(Optional.ofNullable(request.getIsAiGenerated()).orElse(false));

        if (request.getMacros() != null) {
            Macros macros = MacrosMapper.toEntity(request.getMacros());
            recipe.setMacros(macros);
        }

        return recipe;
    }

    /**
     * Updates a Recipe entity with data from a RecipeRequest DTO.
     *
     * @param recipe  The Recipe entity to update
     * @param request The RecipeRequest DTO with updated data
     * @throws IllegalArgumentException if either parameter is null
     * @throws ValidationException      if JSON serialization fails
     */
    public void updateEntityFromRequest(Recipe recipe, RecipeRequest request) {
        if (recipe == null || request == null) {
            throw new IllegalArgumentException("Recipe and request cannot be null");
        }

        recipe.setTitle(request.getTitle());
        recipe.setDescription(request.getDescription());
        recipe.setInstructions(request.getInstructions());

        Optional.ofNullable(request.getImageUrl()).ifPresent(recipe::setImageUrl);
        Optional.ofNullable(request.getIngredients()).ifPresent(i -> recipe.setIngredients(serializeIngredients(i)));
        Optional.ofNullable(request.getTotalTimeMinutes()).ifPresent(recipe::setTotalTimeMinutes);
        Optional.ofNullable(request.getDifficulty()).ifPresent(d -> recipe.setDifficulty(d.name()));
        Optional.ofNullable(request.getIsAiGenerated()).ifPresent(recipe::setIsAiGenerated);

        // Update macros if provided
        if (request.getMacros() != null) {
            if (recipe.getMacros() == null) {
                recipe.setMacros(MacrosMapper.toEntity(request.getMacros()));
            } else {
                MacrosMapper.updateEntityFromDto(recipe.getMacros(), request.getMacros());
            }
        }
    }

    /**
     * Safely converts a String difficulty level to a DifficultyLevel enum.
     */
    private DifficultyLevel toDifficultyLevel(String difficultyStr) {
        if (difficultyStr == null || difficultyStr.trim().isEmpty()) {
            return null;
        }

        try {
            return DifficultyLevel.valueOf(difficultyStr.trim());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid difficulty level: '{}'", difficultyStr);
            return null;
        }
    }

    /**
     * Serializes a list of ingredients to a JSON string.
     */
    private String serializeIngredients(List<String> ingredients) {
        if (ingredients == null || ingredients.isEmpty()) {
            return EMPTY_JSON_ARRAY;
        }

        try {
            if (objectMapper == null) {
                log.error("ObjectMapper not initialized");
                return EMPTY_JSON_ARRAY;
            }
            return objectMapper.writeValueAsString(ingredients);
        } catch (JsonProcessingException e) {
            log.error("Error serializing ingredients: {}", e.getMessage());
            return EMPTY_JSON_ARRAY;
        }
    }

    /**
     * Parses a JSON string into a list of ingredients.
     */
    private List<String> parseIngredients(String ingredientsJson) {
        if (ingredientsJson == null || ingredientsJson.isEmpty() || EMPTY_JSON_ARRAY.equals(ingredientsJson)) {
            return Collections.emptyList();
        }

        try {
            if (objectMapper == null) {
                log.error("ObjectMapper not initialized");
                return Collections.emptyList();
            }
            return objectMapper.readValue(ingredientsJson, INGREDIENTS_TYPE);
        } catch (Exception e) {
            log.error("Error parsing ingredients JSON: {}", e.getMessage());
            return Collections.emptyList();
        }
    }
}