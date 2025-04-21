# User Service - SavorAI

> Backend service providing user management and authentication functionalities for the SavorAI platform. 

This service handles user registration, login, profile management, authorization, and potentially other user-related operations within the SavorAI ecosystem. It utilizes Spring Boot 3 with Java 17, leveraging JWT for secure authentication and JPA for data persistence.

## Table of Contents

*   [Features](#features)
*   [Tech Stack](#tech-stack)
*   [Prerequisites](#prerequisites)
*   [Installation](#installation)
*   [Configuration](#configuration)
*   [Running the Application](#running-the-application)
*   [Running Tests](#running-tests)
*   [API Reference](#api-reference)
*   [Contributing](#contributing)

## Features

*   **User Management:** Core CRUD operations for users. 
*   **Secure Authentication:** JWT-based authentication and authorization using Spring Security.
*   **Data Persistence:** Uses Spring Data JPA with MySQL.
*   **Caching:** Integrated caching using Spring Cache with Caffeine and Redis support.
*   **API Documentation:** Self-documented API using SpringDoc (OpenAPI).
*   **Email Integration:** Capable of sending emails (e.g., for verification, password reset).
*   **Image/Media Handling:** Integrates with Cloudinary. 
*   **Environment-based Configuration:** Uses Spring Dotenv for easy configuration management.

## Tech Stack

*   **Language:** Java 17
*   **Framework:** Spring Boot 3.4.0
*   **Core Modules:** Spring Web, Spring Data JPA, Spring Security, Spring Validation, Spring Actuator, Spring Cache, Spring Mail, Spring Data Redis
*   **Database:** MySQL (Runtime), H2 (Testing)
*   **Caching:** Caffeine, Redis
*   **Authentication:** JWT (via `io.jsonwebtoken:jjwt`)
*   **API Documentation:** SpringDoc OpenAPI (`org.springdoc:springdoc-openapi-starter-webmvc-ui`)
*   **Build Tool:** Gradle 
*   **Utilities:** Lombok, Spring Dotenv
*   **Cloud Services:** Cloudinary
*   **Testing:** JUnit 5, Mockito (via Spring Boot Starter Test), Spring Security Test, Testcontainers

## Prerequisites

*   **Java Development Kit (JDK):** Version 17 or later.
*   **Gradle:** Version compatible with the project (Gradle wrapper included - `./gradlew` commands should work).
*   **MySQL Database:** A running instance accessible by the application. 
*   **Redis Instance:** A running instance accessible by the application. 
*   **(Optional) Docker & Docker Compose:** If used for managing dependencies like MySQL/Redis during development/testing.
*   **(Optional) Cloudinary Account:** API Key, Secret, and Cloud Name if Cloudinary integration is actively used.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url> # <-- Make sure to add your repo URL here!
    cd user-service-SavorAI 
    ```

2.  **Configure Environment:**
    *   Create a `.env` file in the project root directory.
    *   Add necessary environment variables (see [Configuration](#configuration) section below). Key variables include database connection details (`SPRING_DATASOURCE_URL`, `SPRING_DATASOURCE_USERNAME`, `SPRING_DATASOURCE_PASSWORD`), Redis details (`SPRING_REDIS_HOST`, `SPRING_REDIS_PORT`), JWT secret (`JWT_SECRET_KEY`), Cloudinary URL (`CLOUDINARY_URL`), and mail server details.
    *   Alternatively, configure these properties in `src/main/resources/application.properties` or `application.yml` (though `.env` is recommended for secrets).

3.  **Build the project:**
    ```bash
    ./gradlew build 
    ```
    (This will also download dependencies)

## Configuration

The application uses Spring Boot's externalized configuration mechanism, primarily driven by `src/main/resources/application.properties` (or `.yml`) and enhanced by environment variables (via Spring Dotenv, likely reading a `.env` file).

**Key Configuration Properties (Set via `.env` or System Environment Variables):**

*   `SERVER_PORT`: Port the application runs on (default: `8080`).
*   `SPRING_DATASOURCE_URL`: JDBC URL for the MySQL database.
*   `SPRING_DATASOURCE_USERNAME`: Database username.
*   `SPRING_DATASOURCE_PASSWORD`: Database password.
*   `SPRING_JPA_HIBERNATE_DDL_AUTO`: JPA schema generation strategy (e.g., `update`, `validate`, `none`). Use `none` or `validate` for production.
*   `SPRING_REDIS_HOST`: Redis server host.
*   `SPRING_REDIS_PORT`: Redis server port.
*   `JWT_SECRET_KEY`: Secret key for signing JWT tokens (should be strong and kept secure).
*   `JWT_EXPIRATION_MS`: JWT token validity duration in milliseconds.
*   `CLOUDINARY_URL`: Cloudinary connection string (e.g., `cloudinary://API_KEY:API_SECRET@CLOUD_NAME`). 
*   `SPRING_MAIL_HOST`, `SPRING_MAIL_PORT`, `SPRING_MAIL_USERNAME`, `SPRING_MAIL_PASSWORD`: Mail server configuration.
*   `SPRING_PROFILES_ACTIVE`: Active Spring profiles (e.g., `dev`, `prod`).

**Example `.env` structure:**

```dotenv
# .env
SERVER_PORT=8080

SPRING_DATASOURCE_URL=jdbc:mysql://localhost:3306/savorai_users?useSSL=false&serverTimezone=UTC
SPRING_DATASOURCE_USERNAME=your_db_user
SPRING_DATASOURCE_PASSWORD=your_db_password
SPRING_JPA_HIBERNATE_DDL_AUTO=update # Use 'validate' or 'none' in production

SPRING_REDIS_HOST=localhost
SPRING_REDIS_PORT=6379

JWT_SECRET_KEY=YourVeryStrongAndLongSecretKeyShouldGoHereChangeThisImmediately
JWT_EXPIRATION_MS=86400000 # 24 hours

# Optional: Only if using Cloudinary
# CLOUDINARY_URL=cloudinary://<api_key>:<api_secret>@<cloud_name>

# Optional: Mail configuration
# SPRING_MAIL_HOST=smtp.example.com
# SPRING_MAIL_PORT=587
# SPRING_MAIL_USERNAME=user@example.com
# SPRING_MAIL_PASSWORD=password
# SPRING_MAIL_PROPERTIES_MAIL_SMTP_AUTH=true
# SPRING_MAIL_PROPERTIES_MAIL_SMTP_STARTTLS_ENABLE=true 
```
*(Please verify these property names against your application's configuration)*

## Running the Application

Once configured, you can run the application using the Spring Boot Gradle plugin:

```bash
./gradlew bootRun
```

The application will start, and you should see log output indicating it's running, typically on port 8080 (or the port specified in the configuration).

## Running Tests

Execute the unit and integration tests using Gradle:

```bash
./gradlew test
```

Test results will be generated in the `build/reports/tests/test/` directory.

## API Reference

The API is documented using OpenAPI 3. SpringDoc automatically generates the specification.

Once the application is running, you can access the Swagger UI documentation in your browser:

*   **Swagger UI:** [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html) (Replace `8080` if you configured a different port)
*   **OpenAPI Spec (JSON):** [http://localhost:8080/v3/api-docs](http://localhost:8080/v3/api-docs)

This interactive UI allows you to explore endpoints, view request/response models, and even try out API calls directly.

## Contributing

Contributions are welcome! 

We appreciate bug reports, feature requests, and pull requests. Please follow these general steps:

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/your-feature-name`).
3.  Make your changes.
4.  Ensure tests pass (`./gradlew test`).
5.  Commit your changes (`git commit -m 'Add some feature'`).
6.  Push to the branch (`git push origin feature/your-feature-name`).
7.  Open a Pull Request.
