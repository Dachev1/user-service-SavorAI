package dev.idachev.recipeservice.repository;

import dev.idachev.recipeservice.model.Recipe;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface RecipeRepository extends JpaRepository<Recipe, UUID> {

    List<Recipe> findByUserId(UUID userId);

    Page<Recipe> findByTitleContainingIgnoreCaseOrDescriptionContainingIgnoreCase(
            String title, String description, Pageable pageable);
} 