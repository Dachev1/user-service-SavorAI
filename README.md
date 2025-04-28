# SavorAI - User Service

## Overview

The User Service is a foundational microservice in the SavorAI platform, responsible for user authentication, authorization, and user profile management. Built with Spring Boot and Java, this service provides secure and scalable user management capabilities for the entire SavorAI ecosystem.

## Features

- **User Authentication**: Secure sign-up, sign-in, and token-based authentication
- **JWT Token Management**: Generation and validation of JSON Web Tokens
- **User Registration**: Complete user registration flow with email verification
- **Password Management**: Secure password handling with reset functionality
- **Profile Management**: User profile creation and updates
- **Role-Based Authorization**: Support for multiple user roles (User, Admin)
- **Email Communications**: Transactional emails for account verification and notifications
- **Security**: Comprehensive security measures with Spring Security
- **Documentation**: API documentation with Springdoc OpenAPI

## Tech Stack

- **Framework**: Spring Boot 3.4.0
- **Language**: Java 17
- **Database**: MySQL
- **ORM**: Spring Data JPA
- **Security**: Spring Security with JWT
- **API Documentation**: Springdoc OpenAPI
- **Email**: Spring Mail
- **Caching**: Spring Cache with Caffeine
- **Cloud Storage**: Cloudinary for profile images
- **Build Tool**: Gradle
- **Testing**: JUnit, Spring Boot Test, Testcontainers

## Architecture

The User Service follows a clean, layered architecture:

```
dev.idachev.userservice/
├── config/       # Configuration classes for Spring components
├── exception/    # Custom exceptions and error handling
├── model/        # Domain entities and business objects
├── repository/   # Data access layer with JPA repositories
├── security/     # Security configuration and JWT handling
├── service/      # Business logic services
├── util/         # Utility classes and helper functions
├── validation/   # Custom validators and validation logic
├── web/          # REST controllers, DTOs, and request/response mapping
└── Application.java # Main application class
```

## API Endpoints

The service exposes the following main API endpoints:

- **Authentication**:
  - `POST /api/auth/register` - Register a new user
  - `POST /api/auth/login` - Authenticate and get access token
  - `POST /api/auth/refresh` - Refresh access token
  - `POST /api/auth/logout` - Invalidate tokens

- **User Management**:
  - `GET /api/users` - Get users (admin only)
  - `GET /api/users/{id}` - Get user by ID
  - `PUT /api/users/{id}` - Update user
  - `DELETE /api/users/{id}` - Delete user

- **Profile Management**:
  - `GET /api/profile` - Get current user profile
  - `PUT /api/profile` - Update profile
  - `POST /api/profile/image` - Upload profile image

- **Verification**:
  - `GET /api/verification/verify-email` - Verify email address
  - `POST /api/verification/resend` - Resend verification email
  - `POST /api/verification/forgot-password` - Initiate password reset
  - `POST /api/verification/reset-password` - Complete password reset

- **Contact**:
  - `POST /api/contact` - Submit contact form

## Security

The service implements a comprehensive security strategy:

- Argon2 password hashing for maximum security
- JWT-based authentication with refresh tokens
- Role-based access control
- Protection against common vulnerabilities (CSRF, XSS, etc.)
- Rate limiting to prevent brute force attacks
- Input validation and sanitization
- HTTPS enforcement in production
- Secure session management

## Getting Started

### Prerequisites

- JDK 17+
- MySQL 8.0+
- Gradle 8.0+
- SMTP server access (for email functionality)
- Cloudinary account (for image storage)
- Redis instance (optional, for token storage)

### Configuration

Create a `.env` file in the project root with the following variables:

```properties
# Database
DB_URL=jdbc:mysql://localhost:3306/savorai_users
DB_USERNAME=root
DB_PASSWORD=yourpassword

# JWT
JWT_SECRET=your-very-secure-jwt-secret-key
JWT_EXPIRATION=86400000
JWT_REFRESH_EXPIRATION=604800000

# Email
MAIL_HOST=smtp.example.com
MAIL_PORT=587
MAIL_USERNAME=your-email@example.com
MAIL_PASSWORD=your-email-password
MAIL_FROM=noreply@savorai.com

# Application
APP_URL=http://localhost:5173
API_URL=http://localhost:8081

# Cloudinary
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# Redis (for token storage)
REDIS_HOST=localhost
REDIS_PORT=6379
```

### Building and Running

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/user-service-SavorAI.git
   cd user-service-SavorAI
   ```

2. Build the application:
   ```bash
   ./gradlew build
   ```

3. Run the application:
   ```bash
   ./gradlew bootRun
   ```

4. Access the OpenAPI documentation at `http://localhost:8081/swagger-ui.html`

## Testing

Run the tests with the following command:

```bash
./gradlew test
```

The service includes:
- Unit tests for service and utility classes
- Integration tests for repositories
- Controller tests for API endpoints
- Security tests for authentication flows

## Deployment

The service can be deployed in various environments:

### Docker Deployment

1. Build the Docker image:
   ```bash
   ./gradlew bootBuildImage --imageName=savorai/user-service
   ```

2. Run the Docker container:
   ```bash
   docker run -p 8081:8081 savorai/user-service
   ```

### Kubernetes Deployment

1. Create a Kubernetes deployment file (`user-service-deployment.yaml`):
   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: user-service
   spec:
     replicas: 2
     selector:
       matchLabels:
         app: user-service
     template:
       metadata:
         labels:
           app: user-service
       spec:
         containers:
         - name: user-service
           image: savorai/user-service:latest
           ports:
           - containerPort: 8081
           env:
           - name: SPRING_PROFILES_ACTIVE
             value: "prod"
   ```

2. Apply the deployment:
   ```bash
   kubectl apply -f user-service-deployment.yaml
   ```

### Production Considerations

- Use environment-specific configuration profiles
- Set up database replication/clustering for high availability
- Configure proper logging and monitoring
- Implement CI/CD pipelines for automated deployment
- Regular security audits and dependency updates
- Data backup and disaster recovery plans

## Performance Considerations

- The service implements caching for frequently accessed data
- Efficient JWT validation with minimal database lookups
- Database connection pooling
- Asynchronous processing for non-critical operations (email sending)
- Redis for token storage and distributed session management
- Database query optimization and indexing

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Open a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Related Repositories

- [FE-savorAI](https://github.com/yourusername/FE-savorAI) - Frontend application
- [recipe-service-SavorAI](https://github.com/yourusername/recipe-service-SavorAI) - Recipe management service 