# 🍽️ SavorAI User Service

![Java](https://img.shields.io/badge/Java-17-orange)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.x-green)
![MySQL](https://img.shields.io/badge/MySQL-8.0-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

> User authentication and account management microservice for the SavorAI platform. This service handles all user-related operations including registration, authentication, profile management, and security.

## 📑 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [System Architecture](#system-architecture)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Configuration](#configuration)
  - [Installation](#installation)
  - [Running the Application](#running-the-application)
  - [Running Tests](#running-tests)
- [API Documentation](#api-documentation)
  - [Authentication Flow](#authentication-flow)
  - [Core Endpoints](#core-endpoints)
  - [Request/Response Examples](#requestresponse-examples)
- [Project Structure](#project-structure)
- [Code Architecture](#code-architecture)
  - [SOLID Principles Implementation](#solid-principles-implementation)
  - [Exception Handling](#exception-handling)
  - [API Organization](#api-organization)
  - [Security Implementation](#security-implementation)
  - [User Authentication](#user-authentication)
  - [Role-Based Access Control](#role-based-access-control)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Contributing](#contributing)

## 🔍 Overview

SavorAI User Service is a robust microservice designed to handle all user-related operations for the SavorAI platform. Built with security and scalability in mind, it provides comprehensive authentication, authorization, and profile management capabilities through a RESTful API interface.

This service is part of the larger SavorAI ecosystem, working alongside other microservices to provide a complete culinary recommendation and recipe management solution.

## ✨ Features

- **User Management**
  - User registration with email verification
  - Secure authentication using JWT tokens
  - Password reset functionality
  - Account deactivation/deletion

- **Security**
  - JWT-based authentication with refresh tokens
  - Secure password hashing with BCrypt
  - Protection against common security vulnerabilities
  - Token blacklisting for secure logout

- **Access Control**
  - Role-based access control (USER, ADMIN)
  - Fine-grained permission management
  - Method-level security

- **Profile Management**
  - User profile CRUD operations
  - Profile picture management
  - Preference settings

- **API Design**
  - RESTful endpoints with consistent naming
  - Comprehensive error handling
  - API versioning
  - OpenAPI/Swagger documentation

## 🛠️ Technology Stack

### Backend Framework
- **Java 17** - Latest LTS version with modern language features
- **Spring Boot 3.2.x** - Production-grade framework for Java applications
- **Spring Security** - Authentication and authorization framework
- **Spring Data JPA** - Data access abstraction
- **Hibernate** - ORM for database operations

### Database
- **MySQL 8.0+** - Robust relational database for user data storage
- **Flyway** - Database migration tool for version control

### Security
- **JJWT** - Java implementation of JSON Web Tokens
- **BCrypt** - Password hashing algorithm

### Email Services
- **Spring Mail** - Email sending capabilities
- **Thymeleaf** - Template engine for HTML emails

### Documentation
- **Springdoc OpenAPI** - API documentation with Swagger UI
- **Javadoc** - Code documentation

### Testing
- **JUnit 5** - Testing framework
- **Mockito** - Mocking framework for unit tests
- **Testcontainers** - Integration testing with containerized dependencies

### Build & Deployment
- **Gradle 8.x** - Build automation tool
- **Docker** - Containerization for deployment
- **GitHub Actions** - CI/CD pipeline

## 🏗️ System Architecture

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│                 │      │                 │      │                 │
│  Client         │◄────►│  API Gateway    │◄────►│  User Service   │
│  (Web/Mobile)   │      │                 │      │                 │
│                 │      │                 │      │                 │
└─────────────────┘      └─────────────────┘      └────────┬────────┘
                                                           │
                                                           │
                                                           ▼
                                                  ┌─────────────────┐
                                                  │                 │
                                                  │  MySQL Database │
                                                  │                 │
                                                  └─────────────────┘
```

The User Service follows a layered architecture:

1. **Controller Layer** - Handles HTTP requests and responses
2. **Service Layer** - Contains business logic and workflows
3. **Repository Layer** - Manages data access and persistence
4. **Model Layer** - Domain entities and DTOs

## 🚀 Getting Started

### Prerequisites

- **JDK 17+** - Download from [Oracle](https://www.oracle.com/java/technologies/downloads/) or use [AdoptOpenJDK](https://adoptopenjdk.net/)
- **MySQL 8.0+** - [Download and Installation Guide](https://dev.mysql.com/downloads/)
- **Gradle 8.x** - Usually provided by the Gradle wrapper in the project

### Configuration

This service uses environment variables for sensitive configuration. You have two options:

#### Option 1: Environment Variables

```bash
# Database Configuration
export DB_URL=jdbc:mysql://localhost:3306/savorai_users
export DB_USERNAME=your_database_username
export DB_PASSWORD=your_database_password

# Email Service Configuration
export MAIL_HOST=smtp.gmail.com
export MAIL_PORT=587
export MAIL_USERNAME=your_email_username
export MAIL_PASSWORD=your_email_password

# JWT Configuration
export JWT_SECRET=your_jwt_secret_key
export JWT_EXPIRATION=86400000
export JWT_REFRESH_EXPIRATION=604800000
```

#### Option 2: Properties File

Create a `.env.properties` file in `src/main/resources/` with the following content:

```properties
# Database Configuration
DB_URL=jdbc:mysql://localhost:3306/savorai_users
DB_USERNAME=your_database_username
DB_PASSWORD=your_database_password

# Email Service Configuration
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your_email_username
MAIL_PASSWORD=your_email_password

# JWT Configuration
JWT_SECRET=your_jwt_secret_key
JWT_EXPIRATION=86400000
JWT_REFRESH_EXPIRATION=604800000
```

> ⚠️ **Important**: 
> - For Gmail accounts, use an App Password instead of your regular password
> - Create an App Password at [Google Account Security](https://myaccount.google.com/security)
> - Remove any spaces from the App Password when adding it to configuration
> - The JWT secret should be a secure random string of at least 64 characters

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/savorai-user-service.git
cd savorai-user-service

# Create the database
mysql -u root -p
> CREATE DATABASE savorai_users;
> exit

# Build the project
./gradlew build
```

### Running the Application

```bash
# For Windows
./gradlew.bat bootRun

# For Unix/Linux/MacOS
./gradlew bootRun
```

The application will start on port 8081 by default. You can change this in `application.yml` or by setting the `SERVER_PORT` environment variable.

### Running Tests

```bash
# Run all tests
./gradlew test

# Run specific test category
./gradlew test --tests "*.unit.*"
./gradlew test --tests "*.integration.*"
```

## 📝 API Documentation

Once the application is running, access the full OpenAPI/Swagger documentation at:

```
http://localhost:8081/swagger-ui.html
```

### Authentication Flow

```
┌──────────┐                ┌───────────────┐              ┌─────────────┐
│  Client  │                │  User Service │              │  Database   │
└────┬─────┘                └───────┬───────┘              └──────┬──────┘
     │                              │                             │
     │   1. Register                │                             │
     │ ─────────────────────────────>                             │
     │                              │       2. Save User          │
     │                              │ ──────────────────────────> │
     │                              │                             │
     │                              │  3. Send Verification Email │
     │ <─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │                             │
     │                              │                             │
     │   4. Verify Email            │                             │
     │ ─────────────────────────────>                             │
     │                              │      5. Update Status       │
     │                              │ ──────────────────────────> │
     │                              │                             │
     │   6. Login                   │                             │
     │ ─────────────────────────────>                             │
     │                              │     7. Validate User        │
     │                              │ ──────────────────────────> │
     │                              │                             │
     │   8. JWT Token + Refresh     │                             │
     │ <─────────────────────────────                             │
     │                              │                             │
     │   9. Access Protected Resource│                            │
     │ ─────────────────────────────>                             │
     │                              │    10. Validate Token       │
     │                              │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
     │                              │                             │
     │   11. Resource Data          │                             │
     │ <─────────────────────────────                             │
     │                              │                             │
```

### Core Endpoints

| Method | Endpoint | Description | Auth Required | Roles |
|--------|----------|-------------|--------------|-------|
| POST | `/api/v1/auth/register` | Register a new user | No | None |
| POST | `/api/v1/auth/login` | Authenticate a user | No | None |
| POST | `/api/v1/auth/refresh-token` | Refresh access token | No | None |
| POST | `/api/v1/auth/logout` | Logout (blacklist token) | Yes | Any |
| GET | `/api/v1/verification/verify/{token}` | Verify email address | No | None |
| POST | `/api/v1/verification/resend` | Resend verification email | No | None |
| GET | `/api/v1/profile` | Get current user profile | Yes | Any |
| PUT | `/api/v1/profile` | Update user profile | Yes | Any |
| DELETE | `/api/v1/profile` | Delete user account | Yes | Any |
| GET | `/api/v1/user` | List all users (paginated) | Yes | ADMIN |
| GET | `/api/v1/user/{id}` | Get user by ID | Yes | ADMIN |
| PUT | `/api/v1/user/{id}/status` | Update user status | Yes | ADMIN |

### Request/Response Examples

#### Register a New User

**Request:**
```json
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd",
  "firstName": "John",
  "lastName": "Doe"
}
```

**Response:**
```json
HTTP/1.1 201 Created
Content-Type: application/json

{
  "message": "User registered successfully. Please check your email for verification.",
  "userId": "a1b2c3d4-e5f6-7890-abcd-1234567890ab",
  "email": "user@example.com"
}
```

#### Login

**Request:**
```json
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd"
}
```

**Response:**
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "tokenType": "Bearer",
  "expiresIn": 86400,
  "user": {
    "id": "a1b2c3d4-e5f6-7890-abcd-1234567890ab",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "roles": ["USER"]
  }
}
```

## 🗂️ Project Structure

```
src/
├── main/
│   ├── java/
│   │   └── dev.savorai.userservice/
│   │       ├── config/               # Application configuration
│   │       │   ├── SecurityConfig.java     # Security configuration
│   │       │   ├── JwtConfig.java          # JWT configuration
│   │       │   ├── EmailConfig.java        # Email configuration
│   │       │   └── CorsConfig.java         # CORS configuration
│   │       │
│   │       ├── exception/            # Custom exceptions
│   │       │   ├── GlobalExceptionHandler.java  # Central exception handler
│   │       │   ├── ApiException.java            # Base exception class
│   │       │   ├── ResourceNotFoundException.java
│   │       │   ├── InvalidTokenException.java
│   │       │   └── UserAlreadyExistsException.java
│   │       │
│   │       ├── mapper/               # DTO/Entity mappers
│   │       │   ├── UserMapper.java
│   │       │   └── ProfileMapper.java
│   │       │
│   │       ├── model/                # Domain models
│   │       │   ├── entity/                 # JPA entities
│   │       │   │   ├── User.java
│   │       │   │   ├── Role.java
│   │       │   │   ├── VerificationToken.java
│   │       │   │   └── TokenBlacklist.java
│   │       │   │
│   │       │   └── enums/                  # Enumerations
│   │       │       ├── RoleType.java
│   │       │       └── UserStatus.java
│   │       │
│   │       ├── repository/           # Data access layer
│   │       │   ├── UserRepository.java
│   │       │   ├── RoleRepository.java
│   │       │   ├── VerificationTokenRepository.java
│   │       │   └── TokenBlacklistRepository.java
│   │       │
│   │       ├── security/             # Security configurations
│   │       │   ├── JwtTokenProvider.java
│   │       │   ├── JwtAuthenticationFilter.java
│   │       │   ├── UserPrincipal.java
│   │       │   └── UserDetailsServiceImpl.java
│   │       │
│   │       ├── service/              # Business logic services
│   │       │   ├── AuthenticationService.java
│   │       │   ├── TokenService.java
│   │       │   ├── VerificationService.java
│   │       │   ├── ProfileService.java
│   │       │   ├── UserService.java
│   │       │   └── EmailService.java
│   │       │
│   │       ├── web/                  # Web layer
│   │       │   ├── controller/             # REST controllers
│   │       │   │   ├── AuthController.java
│   │       │   │   ├── ProfileController.java
│   │       │   │   ├── VerificationController.java
│   │       │   │   └── UserController.java
│   │       │   │
│   │       │   └── dto/                    # Data Transfer Objects
│   │       │       ├── request/
│   │       │       │   ├── LoginRequest.java
│   │       │       │   ├── RegisterRequest.java
│   │       │       │   └── ProfileUpdateRequest.java
│   │       │       │
│   │       │       └── response/
│   │       │           ├── AuthResponse.java
│   │       │           ├── UserResponse.java
│   │       │           ├── ProfileResponse.java
│   │       │           └── ApiResponse.java
│   │       │
│   │       └── UserServiceApplication.java    # Main application class
│   │
│   └── resources/
│       ├── db/migration/            # Flyway database migrations
│       │   ├── V1__init_schema.sql
│       │   └── V2__add_token_blacklist.sql
│       │
│       ├── templates/               # Email templates
│       │   ├── verification-email.html
│       │   └── password-reset.html
│       │
│       ├── application.yml          # Main application configuration
│       ├── application-dev.yml      # Development configuration
│       └── application-prod.yml     # Production configuration
│
└── test/                           # Test code
    ├── java/
    │   └── dev.savorai.userservice/
    │       ├── unit/                # Unit tests
    │       │   ├── service/
    │       │   └── controller/
    │       │
    │       └── integration/         # Integration tests
    │           ├── controller/
    │           └── repository/
    │
    └── resources/                  # Test resources
        ├── application-test.yml    # Test configuration
        └── data/                   # Test data
```

## 📐 Code Architecture

### SOLID Principles Implementation

The SavorAI User Service has been designed to adhere strictly to SOLID principles:

#### Single Responsibility Principle (SRP)
Each class has one responsibility and one reason to change. Services have been split into specialized components:

- `AuthenticationService`: Manages user registration and authentication flows
- `TokenService`: Handles JWT token generation, validation, and blacklisting
- `VerificationService`: Manages email verification processes
- `ProfileService`: Handles user profile operations
- `UserService`: Provides administrative user management operations
- `EmailService`: Handles email composition and delivery

#### Open/Closed Principle (OCP)
The architecture is designed to be extensible without modifying existing code:

- Abstract classes and interfaces are used where appropriate
- Strategy patterns for authentication methods
- New functionality can be added without changing existing implementations

#### Liskov Substitution Principle (LSP)
Services are designed with clear interfaces and implementations:

- Interface contracts are clear and strictly followed
- Implementation classes can be swapped without affecting consumers
- Subclasses are true specializations of parent classes

#### Interface Segregation Principle (ISP)
Interfaces are client-specific rather than general-purpose:

- Controllers have been segregated by domain responsibility:
  - `AuthController`: Authentication operations
  - `ProfileController`: Profile management
  - `VerificationController`: Email verification
  - `UserController`: User management operations
- Service interfaces are focused on specific use cases

#### Dependency Inversion Principle (DIP)
High-level modules don't depend on low-level modules:

- Services depend on abstractions (interfaces) rather than concrete implementations
- Constructor dependency injection is used throughout the codebase
- Dependencies are explicitly declared and easily testable
- Spring's `@Qualifier` is used when multiple implementations of an interface exist

### Exception Handling

The application implements a centralized exception handling approach:

- `GlobalExceptionHandler` with `@RestControllerAdvice` processes all exceptions
- Custom exception types for different error scenarios:
  - `ResourceNotFoundException`: When a requested resource doesn't exist
  - `InvalidTokenException`: For JWT token validation failures
  - `UserAlreadyExistsException`: When attempting to register with an existing email
- Consistent error response format via `ApiResponse` DTO
- Descriptive error messages with appropriate HTTP status codes
- Validation errors are mapped to readable messages

### API Organization

The API has been organized into logical domains:

- Auth endpoints: `/api/v1/auth/*`
  - Registration, login, token refresh, password reset
- Profile endpoints: `/api/v1/profile/*`
  - User self-service operations
- Verification endpoints: `/api/v1/verification/*`
  - Email verification processes
- User management: `/api/v1/user/*`
  - Administrative user management

Each domain has:
- Consistent naming conventions
- Appropriate HTTP methods for CRUD operations
- Proper request validation
- Comprehensive error handling

### Security Implementation

The application implements a robust security architecture:

1. **JWT-based Authentication Flow**:
   - Token generation with configurable expiration
   - Refresh token mechanism
   - Token blacklisting for secure logout
   - Signature verification on each request

2. **Password Security**:
   - BCrypt password hashing with appropriate work factor
   - Password strength validation
   - Account lockout after failed attempts

3. **Cross-Site Request Forgery (CSRF) Protection**:
   - CSRF tokens for state-changing operations
   - SameSite cookie attributes

4. **Cross-Origin Resource Sharing (CORS)**:
   - Configurable CORS policy
   - Proper handling of preflight requests

### User Authentication

The codebase separates domain model from security concerns:

1. The `User` entity no longer implements Spring Security's `UserDetails` interface
2. A new `UserPrincipal` adapter class:
   - Implements `UserDetails`
   - Wraps the `User` entity
   - Delegates security-related methods to the underlying User entity

This separation provides:
- Cleaner domain model focused on business logic
- Easier security implementation changes without affecting the core model
- Better testability of both security and domain logic
- Clear distinction between authentication and user data

### Role-Based Access Control

The application implements role-based access control with two primary roles:

1. **USER** - Regular application users with standard privileges:
   - Manage their own profile
   - Access personalized content
   - Update their preferences

2. **ADMIN** - Administrative users with elevated privileges:
   - Manage all user accounts
   - View system statistics
   - Configure system settings

Roles are stored in the `User` entity and converted to Spring Security authorities by the `UserPrincipal` class. This enables:

- Declarative security using `@PreAuthorize` annotations
- Method-level security checks with SpEL expressions
- URL pattern-based access restrictions
- Role hierarchy with inheritance

The system is designed to easily add additional roles or fine-grained permissions as the application grows.

## 🚢 Deployment

### Docker Deployment

The application can be containerized using Docker:

```bash
# Build the Docker image
docker build -t savorai-user-service:latest .

# Run the container
docker run -p 8081:8081 \
  -e DB_URL=jdbc:mysql://host.docker.internal:3306/savorai_users \
  -e DB_USERNAME=your_database_username \
  -e DB_PASSWORD=your_database_password \
  -e JWT_SECRET=your_jwt_secret_key \
  -e MAIL_USERNAME=your_email_username \
  -e MAIL_PASSWORD=your_email_password \
  savorai-user-service:latest
```

### Docker Compose

For development environments, you can use Docker Compose:

```yaml
version: '3.8'
services:
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: savorai_users
      MYSQL_USER: savorai
      MYSQL_PASSWORD: savorai_password
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql

  user-service:
    build: .
    depends_on:
      - mysql
    environment:
      DB_URL: jdbc:mysql://mysql:3306/savorai_users
      DB_USERNAME: savorai
      DB_PASSWORD: savorai_password
      JWT_SECRET: your_jwt_secret_key
      MAIL_USERNAME: your_email_username
      MAIL_PASSWORD: your_email_password
    ports:
      - "8081:8081"

volumes:
  mysql_data:
```

## ⚠️ Troubleshooting

### Common Issues

#### Email Authentication Errors

If you encounter `jakarta.mail.AuthenticationFailedException`:

1. Ensure you're using an App Password if using Gmail (with 2FA enabled)
2. Remove any spaces from the App Password
3. Verify the email credentials are correctly set in your configuration
4. Check that your Gmail account allows "Less secure app access" if not using 2FA

#### Database Connection Issues

1. Ensure MySQL is running and accessible
2. Verify the database exists or the user has permission to create it
3. Check database credentials in your configuration
4. Verify the MySQL port is correct (default: 3306)
5. For Docker deployments, ensure proper network configuration

#### JVM Memory Issues

If the application crashes with `OutOfMemoryError`:

1. Increase the JVM heap size: 
   ```
   ./gradlew bootRun -Dorg.gradle.jvmargs="-Xmx1g"
   ```
2. Tune garbage collection parameters for production

#### JWT Token Issues

1. Ensure the JWT secret is sufficiently long and complex
2. Check that the token expiration time is appropriate
3. Verify the system clocks are synchronized for distributed deployments
4. Look for token validation errors in the logs

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your new feature
4. Ensure your code follows the project's coding standards
5. Commit your changes (`git commit -m 'Add some amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request with a detailed description

### Development Practices

- Follow the existing code style
- Write unit tests for all new functionality
- Update documentation for any changed features
- Add comments for complex logic
- Keep pull requests focused on a single concern 