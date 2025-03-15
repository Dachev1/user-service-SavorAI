package dev.idachev.recipeservice.mapper;

import dev.idachev.recipeservice.exception.ValidationException;
import dev.idachev.recipeservice.web.dto.MacrosDto;
import dev.idachev.recipeservice.web.dto.RecipeRequest;
import dev.idachev.recipeservice.web.dto.SimplifiedRecipeResponse;
import lombok.experimental.UtilityClass;

import java.util.Collections;

/**
 * Mapper for AI-related data transformations.
 * Provides methods for converting between AI-generated recipe data and response objects.
 */
@UtilityClass
public class  AIServiceMapper {

    /**
     * Maps a RecipeRequest to a SimplifiedRecipeResponse.
     *
     * @param recipe   the RecipeRequest from AI generation
     * @param imageUrl the generated image URL
     * @return the SimplifiedRecipeResponse
     * @throws ValidationException if recipe is null
     */
    public static SimplifiedRecipeResponse toSimplifiedResponse(RecipeRequest recipe, String imageUrl) {
        if (recipe == null) {
            throw new ValidationException("Recipe cannot be null");
        }

        return SimplifiedRecipeResponse.builder()
                .title(recipe.getTitle())
                .description(recipe.getDescription())
                .instructions(recipe.getInstructions())
                .ingredients(recipe.getIngredients() != null ? recipe.getIngredients() : Collections.emptyList())
                .imageUrl(imageUrl)
                .totalTimeMinutes(recipe.getTotalTimeMinutes())
                .macros(extractMacros(recipe))
                .difficulty(recipe.getDifficulty() != null ? recipe.getDifficulty().toString() : "MEDIUM")
                .build();
    }

    /**
     * Extracts macro nutrients with null safety.
     * 
     * @param recipe the RecipeRequest containing macros data
     * @return a MacrosDto with nutritional information
     */
    private static MacrosDto extractMacros(RecipeRequest recipe) {
        if (recipe == null || recipe.getMacros() == null) {
            return MacrosDto.builder().build();
        }

        return MacrosDto.builder()
                .calories(recipe.getMacros().getCalories())
                .proteinGrams(recipe.getMacros().getProteinGrams())
                .carbsGrams(recipe.getMacros().getCarbsGrams())
                .fatGrams(recipe.getMacros().getFatGrams())
                .build();
    }
} 