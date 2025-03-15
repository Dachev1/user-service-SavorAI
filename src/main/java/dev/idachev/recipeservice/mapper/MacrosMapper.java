package dev.idachev.recipeservice.mapper;

import dev.idachev.recipeservice.model.Macros;
import dev.idachev.recipeservice.web.dto.MacrosDto;
import lombok.experimental.UtilityClass;

/**
 * Mapper for macronutrient transformations.
 * Provides methods for converting between Macros entities and DTOs.
 */
@UtilityClass
public class MacrosMapper {

    /**
     * Converts a Macros entity to a MacrosDto.
     */
    public static MacrosDto toDto(Macros macros) {

        if (macros == null) {
            return null;
        }

        return MacrosDto.builder()
                .calories(macros.getCalories() != null ? macros.getCalories().intValue() : null)
                .proteinGrams(macros.getProteinGrams())
                .carbsGrams(macros.getCarbsGrams())
                .fatGrams(macros.getFatGrams())
                .build();
    }

    /**
     * Converts a MacrosDto to a Macros entity.
     */
    public static Macros toEntity(MacrosDto dto) {

        if (dto == null) {
            return null;
        }

        Macros macros = new Macros();
        macros.setCalories(dto.getCalories() != null ? dto.getCalories().doubleValue() : null);
        macros.setProteinGrams(dto.getProteinGrams());
        macros.setCarbsGrams(dto.getCarbsGrams());
        macros.setFatGrams(dto.getFatGrams());

        return macros;
    }

    /**
     * Updates a Macros entity with data from a MacrosDto.
     */
    public static void updateEntityFromDto(Macros macros, MacrosDto dto) {

        if (macros == null) {
            throw new IllegalArgumentException("Cannot update null macros entity");
        }

        if (dto == null) {
            return;
        }

        macros.setCalories(dto.getCalories() != null ? dto.getCalories().doubleValue() : null);
        macros.setProteinGrams(dto.getProteinGrams());
        macros.setCarbsGrams(dto.getCarbsGrams());
        macros.setFatGrams(dto.getFatGrams());
    }
} 