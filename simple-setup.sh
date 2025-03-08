#!/bin/bash
# SavorAI User Service - Simple Setup Script
# Run this with: source ./simple-setup.sh
# IMPORTANT: This script is for development use only. For production,
# use more secure methods like environment variables in your deployment environment.

# Clear previous environment variables (if any)
unset JWT_SECRET
unset MAIL_PASSWORD
unset DB_USERNAME
unset DB_PASSWORD
unset MAIL_USERNAME
unset ACTUATOR_PASSWORD
unset FRONTEND_URL

# Default values - CHANGE THESE or set them interactively
DB_USERNAME_DEFAULT="root"
DB_PASSWORD_DEFAULT="changeme" # You should change this
MAIL_USERNAME_DEFAULT="your_email@gmail.com" # Change this
ACTUATOR_USERNAME_DEFAULT="actuator"

# Interactive setup
echo -e "\e[36m========= SavorAI User Service Environment Setup =========\e[0m"

read -p "Database username [$DB_USERNAME_DEFAULT]: " input_db_username
export DB_USERNAME="${input_db_username:-$DB_USERNAME_DEFAULT}"

read -sp "Database password: " input_db_password
echo
export DB_PASSWORD="${input_db_password:-$DB_PASSWORD_DEFAULT}"

read -p "Email username [$MAIL_USERNAME_DEFAULT]: " input_mail_username
export MAIL_USERNAME="${input_mail_username:-$MAIL_USERNAME_DEFAULT}"

read -sp "Email password/app password: " input_mail_password
echo
export MAIL_PASSWORD="${input_mail_password}"

read -p "Actuator username [$ACTUATOR_USERNAME_DEFAULT]: " input_actuator_username
export ACTUATOR_USERNAME="${input_actuator_username:-$ACTUATOR_USERNAME_DEFAULT}"

read -sp "Actuator password: " input_actuator_password
echo
export ACTUATOR_PASSWORD="${input_actuator_password}"

read -p "Frontend URL [http://localhost:5173]: " input_frontend_url
export FRONTEND_URL="${input_frontend_url:-http://localhost:5173}"

# Generate a random JWT secret for this development session
echo -e "\e[33mGenerating secure JWT secret...\e[0m"
if [ -f GenerateJwtSecret.class ]; then
    generated_secret=$(java GenerateJwtSecret | grep -oP "^([A-Za-z0-9+/]{43}=)$")
    if [ ! -z "$generated_secret" ]; then
        export JWT_SECRET="$generated_secret"
        echo -e "\e[32mNew JWT secret generated successfully!\e[0m"
    else
        # Generate a fallback secret if Java class fails
        export JWT_SECRET=$(openssl rand -base64 32)
        echo -e "\e[33mGenerated fallback JWT secret\e[0m"
    fi
else
    # Generate a fallback secret if Java class is missing
    export JWT_SECRET=$(openssl rand -base64 32)
    echo -e "\e[33mGenerated fallback JWT secret\e[0m"
    echo -e "\e[33mCompile GenerateJwtSecret.java for more options\e[0m"
fi

# Verify environment variables
echo -e "\n\e[32mEnvironment variables set:\e[0m"
echo -e "\e[36m- DB_USERNAME: $DB_USERNAME\e[0m"
echo -e "\e[36m- DB_PASSWORD: [HIDDEN]\e[0m"
echo -e "\e[36m- JWT_SECRET: [SECURED]\e[0m"
echo -e "\e[36m- MAIL_USERNAME: $MAIL_USERNAME\e[0m"
echo -e "\e[36m- MAIL_PASSWORD: [HIDDEN]\e[0m"
echo -e "\e[36m- ACTUATOR_USERNAME: $ACTUATOR_USERNAME\e[0m"
echo -e "\e[36m- ACTUATOR_PASSWORD: [HIDDEN]\e[0m"
echo -e "\e[36m- FRONTEND_URL: $FRONTEND_URL\e[0m"

echo -e "\n\e[32mYour user service is ready!\e[0m"
echo -e "\e[33mRun with: ./gradlew bootRun\e[0m"
echo -e "\n\e[33mFor production deployment:\e[0m"
echo -e "\e[33m1. Use a securely generated JWT token\e[0m"
echo -e "\e[33m2. Set environment variables through your deployment platform\e[0m"
echo -e "\e[33m3. Never store credentials in code repositories\e[0m" 