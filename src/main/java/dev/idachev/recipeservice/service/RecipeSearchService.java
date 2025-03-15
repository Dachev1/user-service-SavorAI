package dev.idachev.recipeservice.service;

import dev.idachev.recipeservice.exception.ValidationException;
import dev.idachev.recipeservice.mapper.RecipeMapper;
import dev.idachev.recipeservice.model.Recipe;
import dev.idachev.recipeservice.repository.FavoriteRecipeRepository;
import dev.idachev.recipeservice.repository.RecipeRepository;
import dev.idachev.recipeservice.web.dto.RecipeResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service for recipe search operations.
 * Responsible for all search-related functionality.
 */
@Service
@Slf4j
public class RecipeSearchService {

    private final RecipeRepository recipeRepository;
    private final FavoriteRecipeRepository favoriteRecipeRepository;
    private final RecipeMapper recipeMapper;

    public RecipeSearchService(RecipeRepository recipeRepository, FavoriteRecipeRepository favoriteRecipeRepository, RecipeMapper recipeMapper) {
        this.recipeRepository = recipeRepository;
        this.favoriteRecipeRepository = favoriteRecipeRepository;
        this.recipeMapper = recipeMapper;
    }

    /**
     * Search recipes by keyword.
     *
     * @param keyword  Search term
     * @param pageable Pagination information
     * @param userId   Optional user ID for favorite information
     * @return Page of matching recipes
     * @throws ValidationException if pageable is null
     */
    @Transactional(readOnly = true)
    public Page<RecipeResponse> searchRecipes(String keyword, Pageable pageable, UUID userId) {
        if (pageable == null) {
            throw new ValidationException("Pageable cannot be null");
        }

        // If keyword is null or empty, return all recipes
        if (!StringUtils.hasText(keyword)) {
            log.debug("Empty search keyword, returning all recipes");
            return getAllRecipes(pageable, userId);
        }

        log.debug("Searching recipes with keyword: {}", keyword);
        String trimmedKeyword = keyword.trim();

        Page<Recipe> recipePage = recipeRepository.findByTitleContainingIgnoreCaseOrDescriptionContainingIgnoreCase(
                trimmedKeyword, trimmedKeyword, pageable);

        log.debug("Found {} recipes matching keyword: {}", recipePage.getTotalElements(), keyword);
        return mapAndEnhancePage(recipePage, pageable, userId);
    }

    /**
     * Get all recipes with pagination.
     *
     * @param pageable Pagination information
     * @param userId   Optional user ID for favorite information
     * @return Page of recipes
     * @throws ValidationException if pageable is null
     */
    @Transactional(readOnly = true)
    public Page<RecipeResponse> getAllRecipes(Pageable pageable, UUID userId) {
        if (pageable == null) {
            throw new ValidationException("Pageable cannot be null");
        }

        log.debug("Fetching all recipes with pagination: {}", pageable);
        Page<Recipe> recipePage = recipeRepository.findAll(pageable);
        log.debug("Found {} total recipes", recipePage.getTotalElements());

        return mapAndEnhancePage(recipePage, pageable, userId);
    }

    /**
     * Filter recipes by tags.
     * Currently returns all recipes, to be implemented with actual tag filtering.
     *
     * @param filters  List of tag filters
     * @param pageable Pagination information
     * @param userId   Optional user ID for favorite information
     * @return Page of filtered recipes
     * @throws ValidationException if pageable is null
     */
    @Transactional(readOnly = true)
    public Page<RecipeResponse> filterRecipesByTags(List<String> filters, Pageable pageable, UUID userId) {
        if (pageable == null) {
            throw new ValidationException("Pageable cannot be null");
        }

        // TODO: Implement actual tag filtering logic
        if (filters != null && !filters.isEmpty()) {
            log.debug("Filtering recipes by tags: {}", String.join(", ", filters));
        } else {
            log.debug("No filter tags provided, returning all recipes");
        }

        return getAllRecipes(pageable, userId);
    }

    /**
     * Maps recipe entities to responses and enhances them with favorite information.
     *
     * @param recipePage Page of recipe entities
     * @param pageable   Pagination information
     * @param userId     Optional user ID for favorite information
     * @return Page of recipe responses
     */
    private Page<RecipeResponse> mapAndEnhancePage(Page<Recipe> recipePage, Pageable pageable, UUID userId) {
        List<RecipeResponse> responses = recipePage.getContent().stream()
                .map(recipe -> {
                    RecipeResponse response = recipeMapper.toResponse(recipe);
                    return enhanceWithFavoriteInfo(response, userId);
                })
                .collect(Collectors.toList());

        return new PageImpl<>(responses, pageable, recipePage.getTotalElements());
    }

    /**
     * Enhances a recipe response with favorite information.
     *
     * @param response Recipe response to enhance
     * @param userId   Optional user ID
     * @return Enhanced recipe response
     */
    private RecipeResponse enhanceWithFavoriteInfo(RecipeResponse response, UUID userId) {
        if (response == null) {
            return null;
        }

        try {
            // Set favorite count
            long favoriteCount = favoriteRecipeRepository.countByRecipeId(response.getId());
            response.setFavoriteCount(favoriteCount);

            // Set is favorite flag if userId is provided
            if (userId != null) {
                boolean isFavorite = favoriteRecipeRepository.existsByUserIdAndRecipeId(userId, response.getId());
                response.setIsFavorite(isFavorite);
            } else {
                response.setIsFavorite(false);
            }
        } catch (Exception e) {
            log.warn("Error retrieving favorite info: {}", e.getMessage());
            response.setFavoriteCount(0L);
            response.setIsFavorite(false);
        }

        return response;
    }
} 