package dev.idachev.recipeservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.PositiveOrZero;

/**
 * Data Transfer Object for nutritional information (macronutrients).
 * Used in recipe requests and responses to represent nutritional content.
 * All values represent amounts per serving.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Nutritional information (macronutrients) per serving")
public class MacrosDto {
    /**
     * Total calories per serving (kcal)
     */
    @Schema(description = "Total calories per serving in kcal", example = "450")
    @PositiveOrZero(message = "Calories cannot be negative")
    private Integer calories;
    
    /**
     * Protein content in grams per serving
     */
    @Schema(description = "Protein content in grams per serving", example = "12.5")
    @PositiveOrZero(message = "Protein cannot be negative")
    private Double proteinGrams;
    
    /**
     * Carbohydrate content in grams per serving
     */
    @Schema(description = "Carbohydrate content in grams per serving", example = "58.3")
    @PositiveOrZero(message = "Carbs cannot be negative")
    private Double carbsGrams;
    
    /**
     * Fat content in grams per serving
     */
    @Schema(description = "Fat content in grams per serving", example = "18.2")
    @PositiveOrZero(message = "Fat cannot be negative")
    private Double fatGrams;
} 