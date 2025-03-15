package dev.idachev.recipeservice.service;

import dev.idachev.recipeservice.exception.ResourceNotFoundException;
import dev.idachev.recipeservice.exception.ValidationException;
import dev.idachev.recipeservice.mapper.FavoriteRecipeMapper;
import dev.idachev.recipeservice.mapper.RecipeMapper;
import dev.idachev.recipeservice.model.FavoriteRecipe;
import dev.idachev.recipeservice.model.Recipe;
import dev.idachev.recipeservice.repository.FavoriteRecipeRepository;
import dev.idachev.recipeservice.repository.RecipeRepository;
import dev.idachev.recipeservice.web.dto.FavoriteRecipeDto;
import dev.idachev.recipeservice.web.dto.RecipeResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Service for managing favorite recipes.
 */
@Service
@Slf4j
public class FavoriteRecipeService {

    private final FavoriteRecipeRepository favoriteRecipeRepository;
    private final RecipeRepository recipeRepository;
    private final RecipeImageService recipeImageService;
    private final RecipeMapper recipeMapper;

    public FavoriteRecipeService(FavoriteRecipeRepository favoriteRecipeRepository,
                                 RecipeRepository recipeRepository,
                                 RecipeImageService recipeImageService,
                                 RecipeMapper recipeMapper) {
        this.favoriteRecipeRepository = favoriteRecipeRepository;
        this.recipeRepository = recipeRepository;
        this.recipeImageService = recipeImageService;
        this.recipeMapper = recipeMapper;
    }

    /**
     * Add a recipe to user's favorites.
     */
    @Transactional
    public FavoriteRecipeDto addToFavorites(UUID userId, UUID recipeId) {
        if (userId == null) {
            throw new ValidationException("User ID cannot be null");
        }
        if (recipeId == null) {
            throw new ValidationException("Recipe ID cannot be null");
        }

        // Check if already in favorites
        if (favoriteRecipeRepository.existsByUserIdAndRecipeId(userId, recipeId)) {
            log.info("Recipe {} is already in favorites for user {}", recipeId, userId);
            return getFavoriteRecipeDto(userId, recipeId);
        }

        // Get recipe and ensure it exists
        Recipe recipe = findRecipeByIdOrThrow(recipeId);

        // Ensure AI-generated recipes have images
        ensureRecipeHasImage(recipe);

        // Create and save favorite recipe
        FavoriteRecipe favoriteRecipe = createFavoriteRecipe(userId, recipe);
        log.info("Added recipe {} to favorites for user {}", recipeId, userId);

        // Map to DTO with recipe details
        RecipeResponse recipeResponse = recipeMapper.toResponse(recipe);
        return FavoriteRecipeMapper.toDto(favoriteRecipe, recipeResponse);
    }

    /**
     * Create and save a favorite recipe entity.
     */
    private FavoriteRecipe createFavoriteRecipe(UUID userId, Recipe recipe) {
        FavoriteRecipe favoriteRecipe = FavoriteRecipeMapper.create(userId, recipe);
        favoriteRecipe.setAddedAt(LocalDateTime.now());
        return favoriteRecipeRepository.save(favoriteRecipe);
    }

    /**
     * Ensure AI-generated recipe has an image.
     */
    private void ensureRecipeHasImage(Recipe recipe) {
        if (Boolean.TRUE.equals(recipe.getIsAiGenerated()) &&
                (recipe.getImageUrl() == null || recipe.getImageUrl().isEmpty())) {
            log.info("AI-generated recipe {} has no image URL. Generating one.", recipe.getId());
            String imageUrl = recipeImageService.generateRecipeImage(recipe.getTitle(), recipe.getDescription());

            if (imageUrl != null && !imageUrl.isEmpty()) {
                recipe.setImageUrl(imageUrl);
                recipeRepository.save(recipe);
                log.debug("Generated and saved image URL for recipe {}", recipe.getId());
            } else {
                log.warn("Failed to generate image for recipe {}", recipe.getId());
            }
        }
    }

    /**
     * Find recipe by ID or throw exception.
     */
    private Recipe findRecipeByIdOrThrow(UUID recipeId) {
        return recipeRepository.findById(recipeId)
                .orElseThrow(() -> new ResourceNotFoundException("Recipe not found: " + recipeId));
    }

    /**
     * Get a favorite recipe DTO.
     */
    private FavoriteRecipeDto getFavoriteRecipeDto(UUID userId, UUID recipeId) {
        FavoriteRecipe favoriteRecipe = findFavoriteByUserAndRecipeOrThrow(userId, recipeId);
        Recipe recipe = findRecipeByIdOrThrow(recipeId);

        RecipeResponse recipeResponse = recipeMapper.toResponse(recipe);
        return FavoriteRecipeMapper.toDto(favoriteRecipe, recipeResponse);
    }

    /**
     * Find favorite by user and recipe IDs or throw exception.
     */
    private FavoriteRecipe findFavoriteByUserAndRecipeOrThrow(UUID userId, UUID recipeId) {
        return favoriteRecipeRepository.findByUserIdAndRecipeId(userId, recipeId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        String.format("Favorite not found for user %s and recipe %s", userId, recipeId)));
    }

    /**
     * Remove a recipe from user's favorites.
     */
    @Transactional
    public void removeFromFavorites(UUID userId, UUID recipeId) {
        if (userId == null) {
            throw new ValidationException("User ID cannot be null");
        }
        if (recipeId == null) {
            throw new ValidationException("Recipe ID cannot be null");
        }

        FavoriteRecipe favoriteRecipe = findFavoriteByUserAndRecipeOrThrow(userId, recipeId);
        favoriteRecipeRepository.delete(favoriteRecipe);
        log.info("Removed recipe {} from favorites for user {}", recipeId, userId);
    }

    /**
     * Get all favorite recipes for a user with pagination.
     */
    @Transactional(readOnly = true)
    public Page<FavoriteRecipeDto> getUserFavorites(UUID userId, Pageable pageable) {
        if (userId == null) {
            throw new ValidationException("User ID cannot be null");
        }
        if (pageable == null) {
            throw new ValidationException("Pageable cannot be null");
        }

        log.debug("Fetching favorites for user {} with pagination", userId);
        Page<FavoriteRecipe> favoritesPage = favoriteRecipeRepository.findByUserId(userId, pageable);

        // Create a map of recipe IDs to recipes
        Map<UUID, Recipe> recipesMap = getRecipesMapFromFavorites(favoritesPage.getContent());

        // Map favorites to DTOs with recipe details
        return favoritesPage.map(favorite -> mapFavoriteToDto(favorite, recipesMap));
    }

    /**
     * Create a map of recipe IDs to recipe entities.
     */
    private Map<UUID, Recipe> getRecipesMapFromFavorites(List<FavoriteRecipe> favorites) {
        List<UUID> recipeIds = favorites.stream()
                .map(FavoriteRecipe::getRecipeId)
                .toList();

        return recipeRepository.findAllById(recipeIds).stream()
                .collect(Collectors.toMap(Recipe::getId, Function.identity()));
    }

    /**
     * Map a favorite to DTO with recipe details from the recipes map.
     */
    private FavoriteRecipeDto mapFavoriteToDto(FavoriteRecipe favorite, Map<UUID, Recipe> recipesMap) {
        Recipe recipe = recipesMap.get(favorite.getRecipeId());
        RecipeResponse recipeResponse = recipe != null ? recipeMapper.toResponse(recipe) : null;
        return FavoriteRecipeMapper.toDto(favorite, recipeResponse);
    }

    /**
     * Get all favorite recipes for a user without pagination.
     */
    @Transactional(readOnly = true)
    public List<FavoriteRecipeDto> getAllUserFavorites(UUID userId) {
        if (userId == null) {
            throw new ValidationException("User ID cannot be null");
        }

        log.debug("Fetching all favorites for user {}", userId);
        List<FavoriteRecipe> favorites = favoriteRecipeRepository.findByUserId(userId);

        if (favorites.isEmpty()) {
            log.debug("No favorites found for user {}", userId);
            return List.of();
        }

        // Create a map of recipe IDs to recipes
        Map<UUID, Recipe> recipesMap = getRecipesMapFromFavorites(favorites);

        // Map favorites to DTOs with recipe details
        return favorites.stream()
                .map(favorite -> mapFavoriteToDto(favorite, recipesMap))
                .collect(Collectors.toList());
    }

    /**
     * Check if a recipe is in user's favorites.
     */
    @Transactional(readOnly = true)
    public boolean isRecipeInFavorites(UUID userId, UUID recipeId) {
        if (userId == null) {
            throw new ValidationException("User ID cannot be null");
        }
        if (recipeId == null) {
            throw new ValidationException("Recipe ID cannot be null");
        }

        return favoriteRecipeRepository.existsByUserIdAndRecipeId(userId, recipeId);
    }

    /**
     * Get the number of users who have favorited a recipe.
     */
    @Transactional(readOnly = true)
    public long getFavoriteCount(UUID recipeId) {
        if (recipeId == null) {
            throw new ValidationException("Recipe ID cannot be null");
        }

        return favoriteRecipeRepository.countByRecipeId(recipeId);
    }
} 