package dev.idachev.recipeservice.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FavoriteRecipe {

    @Id
    @GeneratedValue
    private UUID id;

    @Column
    private UUID userId;

    @Column
    private UUID recipeId;

    private LocalDateTime addedAt;

    @PrePersist
    protected void onCreate() {
        addedAt = LocalDateTime.now();
    }
}