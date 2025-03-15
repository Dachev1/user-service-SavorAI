package dev.idachev.recipeservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Simplified recipe response with only essential fields.
 * Used for AI-generated recipe suggestions and search previews.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Simplified recipe data for AI-generated suggestions and previews")
public class SimplifiedRecipeResponse {
    @Schema(description = "Recipe title", example = "Spaghetti Carbonara")
    private String title;
    
    @Schema(description = "Recipe description", example = "Classic Italian pasta dish with eggs, cheese, pancetta, and pepper")
    private String description;
    
    @Schema(description = "Step-by-step cooking instructions", example = "1. Boil pasta until al dente\n2. In a separate pan, cook pancetta...")
    private String instructions;
    
    @Schema(description = "List of ingredients required for the recipe", example = "[\"200g spaghetti\", \"100g pancetta\", \"2 large eggs\"]")
    private List<String> ingredients;
    
    @Schema(description = "URL to recipe image", example = "https://example.com/images/carbonara.jpg")
    private String imageUrl;
    
    @Schema(description = "Total preparation and cooking time in minutes", example = "30")
    private Integer totalTimeMinutes;
    
    @Schema(description = "Nutritional information for the recipe")
    private MacrosDto macros;
    
    @Schema(description = "Recipe difficulty level", example = "MEDIUM")
    private String difficulty;
} 