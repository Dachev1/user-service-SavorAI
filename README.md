# SavorAI Recipe Service

## Overview
Backend service for recipe generation and management using OpenAI integration. Allows users to generate custom recipes from ingredients, store favorite recipes, and manage their personal recipe collection.

## Features
- AI-powered recipe generation from ingredients
- Recipe image generation using AI
- User recipe management (create, read, update, delete)
- Favorite recipe functionality
- Recipe search and filtering

## Tech Stack
- Java 17
- Spring Boot 3.2.5
- Spring AI for OpenAI integration
- Spring Security with JWT authentication
- Spring Data JPA for database access
- MySQL database
- Cloudinary for image storage
- Gradle build system

## API Endpoints
The service exposes REST APIs with the following main endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/recipes` | GET | Get all recipes with pagination |
| `/api/v1/recipes/{id}` | GET | Get recipe by ID |
| `/api/v1/recipes` | POST | Create a new recipe |
| `/api/v1/recipes/{id}` | PUT | Update a recipe |
| `/api/v1/recipes/{id}` | DELETE | Delete a recipe |
| `/api/v1/recipes/generate` | POST | Generate a recipe from ingredients |
| `/api/v1/recipes/favorites` | GET | Get user's favorite recipes |
| `/api/v1/recipes/favorites/{recipeId}` | POST | Add recipe to favorites |
| `/api/v1/recipes/favorites/{recipeId}` | DELETE | Remove recipe from favorites |

## Getting Started
1. Configure environment variables in `application.yml`:
   - Database connection
   - OpenAI API key
   - Cloudinary credentials
   - JWT secret

2. Run the service:
   ```
   ./gradlew bootRun
   ```

3. Access API documentation:
   ```
   http://localhost:8082/swagger-ui.html
   ```

## Security
The service uses JWT token-based authentication. All endpoints (except Swagger) require a valid JWT token in the Authorization header. 