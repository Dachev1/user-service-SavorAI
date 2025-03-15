package dev.idachev.recipeservice.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table
@Data
@NoArgsConstructor
public class Recipe {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column
    private String title;

    @Column
    private String description;

    @Column(columnDefinition = "TEXT")
    private String instructions;

    @Column
    private String imageUrl;

    @Column(columnDefinition = "TEXT")
    private String ingredients;

    @Column
    private UUID userId;

    @Column
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column
    private LocalDateTime updatedAt = LocalDateTime.now();

    @Column
    private Integer totalTimeMinutes;

    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true)
    private Macros macros;

    @Column
    private String difficulty;

    @Column
    private Boolean isAiGenerated = false;
} 