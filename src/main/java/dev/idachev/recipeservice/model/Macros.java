package dev.idachev.recipeservice.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Entity
@Table
@Data
@NoArgsConstructor
public class Macros {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column
    private Double calories;

    @Column
    private Double proteinGrams;

    @Column
    private Double carbsGrams;

    @Column
    private Double fatGrams;
} 