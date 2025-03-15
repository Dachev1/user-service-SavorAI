package dev.idachev.recipeservice.repository;

import dev.idachev.recipeservice.model.FavoriteRecipe;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface FavoriteRecipeRepository extends JpaRepository<FavoriteRecipe, UUID> {

    Page<FavoriteRecipe> findByUserId(UUID userId, Pageable pageable);

    List<FavoriteRecipe> findByUserId(UUID userId);

    boolean existsByUserIdAndRecipeId(UUID userId, UUID recipeId);

    long countByRecipeId(UUID recipeId);

    Optional<FavoriteRecipe> findByUserIdAndRecipeId(UUID userId, UUID recipeId);
} 