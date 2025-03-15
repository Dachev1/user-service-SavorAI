package dev.idachev.recipeservice.service;

import dev.idachev.recipeservice.exception.ResourceNotFoundException;
import dev.idachev.recipeservice.exception.UnauthorizedAccessException;
import dev.idachev.recipeservice.exception.ValidationException;
import dev.idachev.recipeservice.infrastructure.ai.AIService;
import dev.idachev.recipeservice.mapper.RecipeMapper;
import dev.idachev.recipeservice.model.Recipe;
import dev.idachev.recipeservice.repository.FavoriteRecipeRepository;
import dev.idachev.recipeservice.repository.RecipeRepository;
import dev.idachev.recipeservice.web.dto.RecipeRequest;
import dev.idachev.recipeservice.web.dto.RecipeResponse;
import dev.idachev.recipeservice.web.dto.SimplifiedRecipeResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@Slf4j
@Tag(name = "Recipe Service", description = "Manages recipe operations")
public class RecipeService {

    private final RecipeRepository recipeRepository;
    private final FavoriteRecipeRepository favoriteRecipeRepository;
    private final RecipeImageService recipeImageService;
    private final RecipeSearchService recipeSearchService;
    private final AIService aiService;
    private final RecipeMapper recipeMapper;

    public RecipeService(RecipeRepository recipeRepository, FavoriteRecipeRepository favoriteRecipeRepository, RecipeImageService recipeImageService, RecipeSearchService recipeSearchService, AIService aiService, RecipeMapper recipeMapper) {
        this.recipeRepository = recipeRepository;
        this.favoriteRecipeRepository = favoriteRecipeRepository;
        this.recipeImageService = recipeImageService;
        this.recipeSearchService = recipeSearchService;
        this.aiService = aiService;
        this.recipeMapper = recipeMapper;
    }

    /**
     * Create a new recipe with an optional image upload.
     *
     * @param request Recipe data to create
     * @param image   Optional image file for the recipe
     * @param userId  ID of the user creating the recipe
     * @return Created recipe response with enhanced information
     * @throws ValidationException if request validation fails
     */
    @Operation(summary = "Create a new recipe with optional image upload")
    @Transactional
    public RecipeResponse createRecipe(RecipeRequest request, MultipartFile image, UUID userId) {
        validateRequest(request, userId);

        // Process image if provided
        processImageIfPresent(request, image);

        // Create and save recipe
        Recipe recipe = recipeMapper.toEntity(request);
        recipe.setUserId(userId);
        recipe.setCreatedAt(LocalDateTime.now());
        recipe.setUpdatedAt(LocalDateTime.now());

        Recipe savedRecipe = recipeRepository.save(recipe);
        log.info("Created recipe with ID: {}", savedRecipe.getId());

        return enhanceWithFavoriteInfo(recipeMapper.toResponse(savedRecipe), userId);
    }

    /**
     * Process and attach image URL to the recipe request if an image is provided
     */
    private void processImageIfPresent(RecipeRequest request, MultipartFile image) {
        if (image != null && !image.isEmpty()) {
            String imageUrl = recipeImageService.processRecipeImage(
                    request.getTitle(), request.getDescription(), image);

            if (imageUrl != null && !imageUrl.isEmpty()) {
                request.setImageUrl(imageUrl);
                log.debug("Image processed and URL attached to recipe request");
            } else {
                log.warn("Image processing returned null or empty URL");
            }
        }
    }

    /**
     * Validate recipe request and user ID
     *
     * @throws ValidationException if validation fails
     */
    private void validateRequest(RecipeRequest request, UUID userId) {
        if (request == null) {
            throw new ValidationException("Recipe request cannot be null");
        }

        if (userId == null) {
            throw new ValidationException("User ID cannot be null");
        }

        // Additional validation logic
        if (request.getTitle() == null || request.getTitle().trim().isEmpty()) {
            throw new ValidationException("Recipe title cannot be empty");
        }

        if (request.getInstructions() == null || request.getInstructions().trim().isEmpty()) {
            throw new ValidationException("Recipe instructions cannot be empty");
        }

        if (request.getIngredients() == null || request.getIngredients().isEmpty()) {
            throw new ValidationException("Recipe must have at least one ingredient");
        }
    }

    /**
     * Create a recipe without image upload.
     *
     * @param request Recipe data to create
     * @param userId  ID of the user creating the recipe
     * @return Created recipe response with enhanced information
     * @throws ValidationException if request validation fails
     */
    @Operation(summary = "Create a recipe without image upload")
    @Transactional
    public RecipeResponse createRecipe(RecipeRequest request, UUID userId) {
        return createRecipe(request, null, userId);
    }

    /**
     * Get a recipe by ID.
     *
     * @param id     Recipe ID
     * @param userId Optional user ID for favorite information
     * @return Recipe response with enhanced information
     * @throws ValidationException       if ID is null
     * @throws ResourceNotFoundException if recipe not found
     */
    @Operation(summary = "Get a recipe by ID")
    @Transactional(readOnly = true)
    public RecipeResponse getRecipeById(UUID id, UUID userId) {
        if (id == null) {
            throw new ValidationException("Recipe ID cannot be null");
        }

        Recipe recipe = findRecipeByIdOrThrow(id);
        return enhanceWithFavoriteInfo(recipeMapper.toResponse(recipe), userId);
    }

    /**
     * Find a recipe by ID or throw an exception if not found
     *
     * @param id Recipe ID
     * @return Recipe if found
     * @throws ResourceNotFoundException if recipe not found
     */
    private Recipe findRecipeByIdOrThrow(UUID id) {
        return recipeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Recipe not found with id: " + id));
    }


    /**
     * Get all recipes with pagination and favorite information.
     *
     * @param pageable Pagination information
     * @param userId   Optional user ID for favorite information
     * @return Paged list of recipes
     */
    @Operation(summary = "Get all recipes with pagination")
    @Transactional(readOnly = true)
    public Page<RecipeResponse> getAllRecipes(Pageable pageable, UUID userId) {
        return recipeSearchService.getAllRecipes(pageable, userId);
    }


    /**
     * Get recipes by user ID.
     *
     * @param userId User ID
     * @return List of recipes created by the user
     * @throws ValidationException if user ID is null
     */
    @Operation(summary = "Get recipes by user ID")
    @Transactional(readOnly = true)
    public List<RecipeResponse> getRecipesByUserId(UUID userId) {
        if (userId == null) {
            throw new ValidationException("User ID cannot be null");
        }

        return recipeRepository.findByUserId(userId).stream()
                .map(recipeMapper::toResponse)
                .map(response -> enhanceWithFavoriteInfo(response, userId))
                .toList();
    }

    /**
     * Update an existing recipe.
     *
     * @param id      Recipe ID to update
     * @param request Updated recipe data
     * @param userId  ID of the user updating the recipe
     * @return Updated recipe response
     * @throws ValidationException         if validation fails
     * @throws ResourceNotFoundException   if recipe not found
     * @throws UnauthorizedAccessException if user doesn't own the recipe
     */
    @Operation(summary = "Update an existing recipe")
    @Transactional
    public RecipeResponse updateRecipe(UUID id, RecipeRequest request, UUID userId) {
        if (id == null) {
            throw new ValidationException("Recipe ID cannot be null");
        }

        if (request == null) {
            throw new ValidationException("Recipe request cannot be null");
        }

        if (userId == null) {
            throw new ValidationException("User ID cannot be null");
        }

        Recipe recipe = checkRecipePermission(id, userId);

        recipeMapper.updateEntityFromRequest(recipe, request);
        recipe.setUpdatedAt(LocalDateTime.now());

        Recipe updatedRecipe = recipeRepository.save(recipe);
        log.info("Updated recipe with ID: {}", updatedRecipe.getId());

        return enhanceWithFavoriteInfo(recipeMapper.toResponse(updatedRecipe), userId);
    }

    /**
     * Delete a recipe.
     *
     * @param id     Recipe ID to delete
     * @param userId ID of the user deleting the recipe
     * @throws ValidationException         if validation fails
     * @throws ResourceNotFoundException   if recipe not found
     * @throws UnauthorizedAccessException if user doesn't own the recipe
     */
    @Operation(summary = "Delete a recipe")
    @Transactional
    public void deleteRecipe(UUID id, UUID userId) {
        Recipe recipe = checkRecipePermission(id, userId);
        recipeRepository.delete(recipe);
        log.info("Recipe with ID {} deleted successfully", id);
    }

    /**
     * Search recipes by keyword.
     *
     * @param keyword  Search keyword
     * @param pageable Pagination information
     * @param userId   Optional user ID for favorite information
     * @return Paged list of matching recipes
     */
    @Operation(summary = "Search recipes by keyword")
    @Transactional(readOnly = true)
    public Page<RecipeResponse> searchRecipes(String keyword, Pageable pageable, UUID userId) {
        if (pageable == null) {
            throw new ValidationException("Pageable cannot be null");
        }
        return recipeSearchService.searchRecipes(keyword, pageable, userId);
    }

    /**
     * Generate a meal from ingredients
     *
     * @param ingredients List of ingredients
     * @return Generated recipe response
     * @throws ValidationException if ingredients list is empty
     */
    @Operation(summary = "Generate a recipe from ingredients")
    public SimplifiedRecipeResponse generateMeal(List<String> ingredients) {

        if (ingredients == null || ingredients.isEmpty()) {
            throw new ValidationException("Ingredients list cannot be empty");
        }
        log.info("Generating meal from {} ingredients", ingredients.size());
        return aiService.generateRecipeFromIngredients(ingredients);
    }

    /**
     * Check if a user has permission to modify a recipe.
     *
     * @param recipeId Recipe ID
     * @param userId   User ID
     * @return Recipe if user has permission
     * @throws ValidationException         if validation fails
     * @throws ResourceNotFoundException   if recipe not found
     * @throws UnauthorizedAccessException if user doesn't own the recipe
     */
    private Recipe checkRecipePermission(UUID recipeId, UUID userId) {
        if (recipeId == null) {
            throw new ValidationException("Recipe ID cannot be null");
        }

        if (userId == null) {
            throw new ValidationException("User ID cannot be null");
        }

        Recipe recipe = findRecipeByIdOrThrow(recipeId);

        if (!recipe.getUserId().equals(userId)) {
            log.warn("Unauthorized access attempt: User {} attempted to access recipe {}", userId, recipeId);
            throw new UnauthorizedAccessException("You do not have permission to modify this recipe");
        }

        return recipe;
    }

    /**
     * Enhance a recipe response with favorite information.
     *
     * @param response Recipe response to enhance
     * @param userId   Optional user ID for favorite information
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

            // Set is favorite for the current user if userId is provided
            boolean isFavorite = userId != null &&
                    favoriteRecipeRepository.existsByUserIdAndRecipeId(userId, response.getId());
            response.setIsFavorite(isFavorite);
        } catch (Exception e) {
            log.warn("Error enhancing recipe {} with favorite info: {}", response.getId(), e.getMessage());
            response.setFavoriteCount(0L);
            response.setIsFavorite(false);
        }

        return response;
    }
} 