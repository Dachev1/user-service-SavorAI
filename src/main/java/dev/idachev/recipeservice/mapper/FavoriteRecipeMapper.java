package dev.idachev.recipeservice.mapper;

import dev.idachev.recipeservice.model.FavoriteRecipe;
import dev.idachev.recipeservice.model.Recipe;
import dev.idachev.recipeservice.web.dto.FavoriteRecipeDto;
import dev.idachev.recipeservice.web.dto.RecipeResponse;
import lombok.experimental.UtilityClass;

import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Mapper for favorite recipe transformations.
 * Provides methods for converting between FavoriteRecipe entities and DTOs.
 */
@UtilityClass
public class FavoriteRecipeMapper {

    /**
     * Converts a FavoriteRecipe entity to a FavoriteRecipeDto with optional recipe data.
     */
    public static FavoriteRecipeDto toDto(FavoriteRecipe favoriteRecipe, RecipeResponse recipeResponse) {

        if (favoriteRecipe == null) {
            throw new IllegalArgumentException("Cannot convert null favoriteRecipe to DTO");
        }

        return FavoriteRecipeDto.builder()
                .recipeId(favoriteRecipe.getRecipeId())
                .userId(favoriteRecipe.getUserId())
                .addedAt(favoriteRecipe.getAddedAt())
                .recipe(recipeResponse)
                .build();
    }


    /**
     * Creates a new FavoriteRecipe entity.
     */
    public static FavoriteRecipe create(UUID userId, UUID recipeId) {

        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }

        if (recipeId == null) {
            throw new IllegalArgumentException("Recipe ID cannot be null");
        }

        return FavoriteRecipe.builder()
                .userId(userId)
                .recipeId(recipeId)
                .build();
    }

    /**
     * Creates a new FavoriteRecipe entity from a Recipe entity.
     */
    public static FavoriteRecipe create(UUID userId, Recipe recipe) {

        if (recipe == null) {
            throw new IllegalArgumentException("Recipe cannot be null");
        }

        return create(userId, recipe.getId());
    }
} 