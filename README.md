# SavorAI User Service

## Environment Variables Setup

This application requires certain environment variables to be set for proper operation. Sensitive data such as passwords and secrets should never be committed to the repository.

### Setup Instructions

1. Copy the `.env.example` file to a new file named `.env`:
   ```
   cp .env.example .env
   ```

2. Edit the `.env` file and fill in your actual values:
   ```
   # Database Configuration
   DB_USERNAME=actual_username
   DB_PASSWORD=actual_password
   
   # Email Configuration
   MAIL_USERNAME=your_actual_email@gmail.com
   MAIL_PASSWORD=your_actual_app_password
   
   # Security Configuration
   ACTUATOR_PASSWORD=your_actual_secure_password
   
   # JWT Configuration
   JWT_SECRET=your_actual_very_long_and_secure_random_string
   ```

3. Make sure the `.env` file is never committed to your repository (it should be listed in `.gitignore`).

### Running the Application with Environment Variables

#### Using Maven:
```bash
# Linux/macOS
source .env && mvn spring-boot:run

# Windows (PowerShell)
Get-Content .env | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' -and -not $_.StartsWith('#') } | ForEach-Object { $var = $_.Split('=', 2); [Environment]::SetEnvironmentVariable($var[0], $var[1], 'Process') }
mvn spring-boot:run
```

#### Using Docker:
```bash
docker run --env-file .env -p 8081:8081 savorai/user-service
```

## Alternative: Using Spring Profiles

You can also use Spring profiles for different environments:

1. Create specific application-{profile}.yml files (e.g., application-dev.yml, application-prod.yml)
2. Keep sensitive data out of these files
3. Set environment variables in each environment
4. Run the application with the specific profile:
   ```
   java -jar user-service.jar --spring.profiles.active=prod
   ```

## Security Best Practices

- Never commit sensitive data to your repository
- Use different secrets in different environments
- Regularly rotate passwords and secrets
- Consider using a secrets management solution like HashiCorp Vault, AWS Secrets Manager, or Spring Cloud Config Server for production 