package dev.idachev.recipeservice.web;

import dev.idachev.recipeservice.service.FavoriteRecipeService;
import dev.idachev.recipeservice.user.dto.UserDTO;
import dev.idachev.recipeservice.user.service.UserService;
import dev.idachev.recipeservice.web.dto.FavoriteRecipeDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Controller for managing favorite recipes.
 * Follows RESTful principles for HTTP methods and status codes.
 * All exceptions are handled by the GlobalExceptionHandler.
 */
@RestController
@RequestMapping("/api/v1/favorites")
@Slf4j
@Tag(name = "Favorites", description = "API for managing favorite recipes")
public class FavoriteRecipeController {

    private final FavoriteRecipeService favoriteRecipeService;
    private final UserService userService;

    @Autowired
    public FavoriteRecipeController(FavoriteRecipeService favoriteRecipeService, UserService userService) {
        this.favoriteRecipeService = favoriteRecipeService;
        this.userService = userService;
    }

    @Operation(summary = "Add recipe to favorites", description = "Adds a recipe to the current user's favorites")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Recipe added to favorites", 
                    content = @Content(schema = @Schema(implementation = FavoriteRecipeDto.class))),
            @ApiResponse(responseCode = "404", description = "Recipe not found"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PostMapping("/{recipeId}")
    public ResponseEntity<FavoriteRecipeDto> addToFavorites(
            @Parameter(description = "ID of the recipe to add to favorites")
            @PathVariable UUID recipeId,
            @RequestHeader("Authorization") String token) {

        UUID userId = getUserIdFromToken(token);
        return ResponseEntity.ok(favoriteRecipeService.addToFavorites(userId, recipeId));
    }

    @Operation(summary = "Remove recipe from favorites", description = "Removes a recipe from the current user's favorites")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Recipe removed from favorites"),
            @ApiResponse(responseCode = "404", description = "Recipe not found in favorites"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @DeleteMapping("/{recipeId}")
    public ResponseEntity<Void> removeFromFavorites(
            @Parameter(description = "ID of the recipe to remove from favorites")
            @PathVariable UUID recipeId,
            @RequestHeader("Authorization") String token) {

        UUID userId = getUserIdFromToken(token);
        favoriteRecipeService.removeFromFavorites(userId, recipeId);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Get user's favorite recipes", description = "Returns the current user's favorite recipes with pagination")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "List of favorite recipes returned", 
                    content = @Content(schema = @Schema(implementation = Page.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping
    public ResponseEntity<Page<FavoriteRecipeDto>> getUserFavorites(
            @Parameter(description = "Pagination parameters")
            Pageable pageable,
            @RequestHeader("Authorization") String token) {

        UUID userId = getUserIdFromToken(token);
        return ResponseEntity.ok(favoriteRecipeService.getUserFavorites(userId, pageable));
    }

    @Operation(summary = "Get all user's favorites", description = "Returns all favorite recipes for the current user")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "List of all favorite recipes returned", 
                    content = @Content(schema = @Schema(implementation = FavoriteRecipeDto.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/all")
    public ResponseEntity<List<FavoriteRecipeDto>> getAllUserFavorites(
            @RequestHeader("Authorization") String token) {

        UUID userId = getUserIdFromToken(token);
        return ResponseEntity.ok(favoriteRecipeService.getAllUserFavorites(userId));
    }

    @Operation(summary = "Check if recipe is in favorites", description = "Checks if a recipe is in the current user's favorites")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Returns true if recipe is in favorites, false otherwise", 
                    content = @Content(schema = @Schema(implementation = Boolean.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/check/{recipeId}")
    public ResponseEntity<Boolean> isRecipeInFavorites(
            @Parameter(description = "ID of the recipe to check")
            @PathVariable UUID recipeId,
            @RequestHeader("Authorization") String token) {

        UUID userId = getUserIdFromToken(token);
        return ResponseEntity.ok(favoriteRecipeService.isRecipeInFavorites(userId, recipeId));
    }

    @Operation(summary = "Get favorite count", description = "Returns the number of users who have favorited a recipe")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Favorite count returned", 
                    content = @Content(schema = @Schema(implementation = Long.class)))
    })
    @GetMapping("/count/{recipeId}")
    public ResponseEntity<Long> getFavoriteCount(
            @Parameter(description = "ID of the recipe")
            @PathVariable UUID recipeId) {

        return ResponseEntity.ok(favoriteRecipeService.getFavoriteCount(recipeId));
    }

    /**
     * Helper method to extract userId from authentication token
     */
    private UUID getUserIdFromToken(String token) {
        UserDTO user = userService.getCurrentUser(token);
        return userService.getUserIdFromUsername(user.getUsername());
    }
} 