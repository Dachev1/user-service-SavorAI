package dev.idachev.recipeservice.infrastructure.ai;

/**
 * Centralized storage for AI prompts used in recipe generation
 */
public class RecipePrompts {

    /**
     * System prompt for generating a recipe from ingredients
     */
    public static String getRecipeFromIngredientsPrompt() {
        return """
            You are an expert chef and nutritionist specializing in creating delicious, practical recipes.
            
            Your task is to create ONE detailed recipe using the ingredients provided by the user. Be creative but realistic.
            Include common pantry staples (salt, pepper, oil, basic spices) even if not explicitly listed.
            
            IMPORTANT: EVERY TIME YOU ARE ASKED, CREATE A COMPLETELY DIFFERENT RECIPE, EVEN IF THE INGREDIENTS ARE THE SAME.
            Pay attention to any style, cuisine, or cooking method specified in the user's request.
            
            FORMAT YOUR RESPONSE AS VALID JSON with this exact structure:
            {
                "title": "Recipe Title",
                "description": "A mouth-watering description that makes someone want to cook this dish",
                "ingredients": ["Ingredient 1 with quantity", "Ingredient 2 with quantity", ...],
                "instructions": "Detailed, step-by-step cooking instructions with numbered steps",
                "totalTimeMinutes": number (prep + cooking time),
                "macros": {
                    "calories": number,
                    "proteinGrams": number,
                    "carbsGrams": number,
                    "fatGrams": number
                },
                "difficulty": "EASY", "MEDIUM", or "HARD"
            }
            
            IMPORTANT GUIDELINES:
            1. Make the dish realistic and achievable for a home cook
            2. Be precise with measurements and quantities
            3. Estimate nutrition information realistically
            4. Create visually appealing dishes that would photograph well
            5. Instructions should be clear and easy to follow
            6. ALWAYS CREATE A DIFFERENT RECIPE - never repeat a recipe you've created before
            
            Return ONLY the JSON object, no additional text.
            """;
    }
    
    /**
     * Prompt for generating a recipe image
     */
    public static String getRecipeImagePrompt(String recipeTitle, String recipeDescription) {
        return "Professional food photography of " + recipeTitle + 
               ". Overhead shot on a rustic wooden table with beautiful natural lighting. " +
               "The dish looks absolutely delicious with vibrant colors and perfect presentation. " +
               "Show the complete dish styled by a food photographer. " + 
               "Food description: " + (recipeDescription != null ? recipeDescription : "");
    }
    
    /**
     * Prompt template for unique recipe generation from ingredients
     * 
     * @param ingredients Comma-separated list of ingredients
     * @param uniqueId Unique identifier for the recipe
     * @return Formatted prompt text
     */
    public static String getUniqueRecipePrompt(String ingredients, String uniqueId) {
        return String.format(
            "I need a creative and unique recipe using these ingredients: %s. " +
            "Please create a dish that makes the best use of these ingredients. " +
            "Be creative with the cuisine style, cooking method, and meal type. " +
            "Make it unique with ID: %s",
            ingredients, uniqueId
        );
    }
} 