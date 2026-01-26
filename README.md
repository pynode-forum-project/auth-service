# Auth Service

The Auth Service is a microservice responsible for user authentication, registration, email verification, and JWT token management.

## Features

- **User Login**: Authentication via email and password with JWT token issuance
- **User Registration**: New user registration and email verification token delivery
- **Email Verification**: Email verification via 6-digit verification code
- **Token Refresh**: JWT token refresh functionality
- **Password Encryption**: Secure password hashing using bcrypt
- **Input Validation**: Validation of input data including email, password, and names

## Tech Stack

- **Framework**: Flask 3.0.0
- **Authentication**: PyJWT 2.8.0
- **Password Hashing**: bcrypt 4.1.2
- **Message Queue**: pika 1.3.2 (RabbitMQ)
- **HTTP Client**: requests 2.31.0
- **CORS**: Flask-Cors 4.0.0

## Project Structure

```
auth-service/
├── app/
│   ├── __init__.py          # Flask app initialization
│   ├── config.py            # Configuration management
│   ├── routes/
│   │   ├── __init__.py
│   │   └── auth_routes.py   # Authentication API endpoints
│   ├── services/
│   │   ├── __init__.py
│   │   ├── auth_service.py  # Authentication business logic
│   │   ├── user_client.py   # User Service HTTP client
│   │   └── message_queue.py # RabbitMQ message queue client
│   └── utils/
│       ├── __init__.py
│       ├── validators.py     # Input validation utilities
│       ├── decorators.py     # Decorators (exception handling, etc.)
│       └── error_handlers.py # Error handlers
├── Dockerfile               # Docker image build file
├── requirements.txt         # Python dependencies
├── run.py                   # Application entry point
└── README.md                # Project documentation
```

## Environment Variables

Create a `.env` file and set the following environment variables:

```env
# Flask settings
SECRET_KEY=your-secret-key-here
FLASK_ENV=development

# JWT settings
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRATION_HOURS=24

# Service URLs
USER_SERVICE_URL=http://localhost:5001

# RabbitMQ settings
RABBITMQ_URL=amqp://guest:guest@localhost:5672

# Email verification token settings
VERIFICATION_TOKEN_HOURS=3
```

## Installation and Running

### Local Development

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set Environment Variables**
   Create a `.env` file and configure the required environment variables.

3. **Run the Application**
   ```bash
   python run.py
   ```
   
   The service runs on `http://localhost:5000` by default.

### Using Docker

1. **Build Docker Image**
   ```bash
   docker build -t auth-service .
   ```

2. **Run Container**
   ```bash
   docker run -p 5000:5000 --env-file .env auth-service
   ```

## API Endpoints

### 1. User Login
**POST** `/login`

Request Body:
```json
{
  "email": "user@example.com",
  "password": "Password123!"
}
```

Success Response (200):
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "userId": 1,
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "type": "user",
    "active": true,
    "profileImageUrl": null
  }
}
```

### 2. User Registration
**POST** `/register`

Request Body:
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "user@example.com",
  "password": "Password123!"
}
```

Success Response (201):
```json
{
  "message": "Registration successful. Please check your email to verify your account.",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "userId": 1,
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "type": "user"
  }
}
```

### 3. Email Verification
**POST** `/verify-email`

Request Body:
```json
{
  "email": "user@example.com",
  "token": "123456"
}
```

Success Response (200):
```json
{
  "message": "Email verified successfully",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "userId": 1,
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "type": "user",
    "active": true,
    "profileImageUrl": null
  }
}
```

### 4. Resend Verification Email
**POST** `/resend-verification`

Request Body:
```json
{
  "email": "user@example.com"
}
```

Success Response (200):
```json
{
  "message": "Verification email sent"
}
```

### 5. Refresh Token
**POST** `/refresh-token`

Request Headers:
```
Authorization: Bearer <token>
```

Success Response (200):
```json
{
  "message": "Token refreshed",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 6. Health Check
**GET** `/health`

Response:
```json
{
  "status": "healthy",
  "service": "auth-service"
}
```

## Password Requirements

Passwords must meet the following criteria:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character (`!@#$%^&*(),.?":{}|<>`)

## External Service Integration

### User Service
- User information retrieval and creation
- Email verification token management
- User status updates

### Email Service (RabbitMQ)
- Email verification code delivery
- Notification email delivery

Required Queues:
- `email.verification`: Email verification messages
- `email.notification`: Notification messages

## Error Handling

The service handles the following errors:
- **400**: Bad Request (validation failures, etc.)
- **401**: Unauthorized (invalid email/password, invalid token)
- **403**: Forbidden (account deactivated)
- **404**: Not Found
- **409**: Conflict (email already exists, etc.)
- **500**: Internal Server Error

## Security Considerations

1. **JWT Tokens**: Signed using HS256 algorithm
2. **Password Hashing**: Secure hashing using bcrypt (12 rounds)
3. **Environment Variables**: Sensitive information managed via environment variables
4. **CORS**: Recommended to allow only specific origins in production environment

## Development Guide

### Code Structure
- **routes/**: API endpoint definitions
- **services/**: Business logic and external service integration
- **utils/**: Utility functions (validation, error handling, etc.)

### Logging
The application uses Python's `logging` module to record logs.

### Testing
To run tests:
```bash
# If test files exist
pytest
```

## License

Refer to the `LICENSE` file for license information.
