# Auth Service

Auth Service is a Flask-based microservice that handles user authentication for the Forum Project.

## Features

- **User Registration**: POST `/auth/register` - Register new users
- **User Login**: POST `/auth/login` - Verify credentials and generate JWT tokens
- **JWT Token Verification**: POST `/auth/verify-token` - Verify JWT token validity
- **Route Protection**: Middleware decorators (`@login_required`, `@admin_required`) for protecting routes

## API Endpoints

### POST /auth/register
Register a new user account.

**Request Body:**
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "message": "Registration successful",
  "user_id": "uuid-string"
}
```

### POST /auth/login
Login and receive JWT token.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user_id": "uuid-string",
  "user_type": "normal_user",
  "isActive": false
}
```

**Note:** 
- Password is hashed using bcrypt before storing in database.
- Email verification is handled separately in user profile or other services.
- Users with `isActive: false` can login but have limited permissions (can view posts but cannot create posts or replies).
- JWT token contains `user_id`, `user_type`, and `is_active` for authorization.

### POST /auth/verify-token
Verify if a JWT token is valid (protected route example).

**Request Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "valid": true,
  "user_id": "uuid-string",
  "user_type": "normal_user",
  "is_active": false
}
```

## JWT Utilities

The service provides utility functions and decorators for JWT token management:

### Functions
- `generate_token(user_id, user_type, is_active)`: Generate a JWT token
- `decode_token(token)`: Decode and verify a JWT token
- `verify_token(token)`: Verify JWT token and return decoded payload
- `get_token_from_header()`: Extract JWT token from Authorization header

### Decorators
- `@login_required`: Protect routes requiring authentication
  - Attaches `request.current_user_id`, `request.current_user_type`, `request.current_user_is_active` to request object
- `@admin_required`: Protect routes requiring admin privileges
  - Requires `user_type` to be 'admin' or 'super_admin'

### Usage Example
```python
from app.utils.jwt_utils import login_required, admin_required

@auth_bp.route('/protected')
@login_required
def protected_route():
    user_id = request.current_user_id
    return jsonify({'user_id': user_id})

@auth_bp.route('/admin-only')
@login_required
@admin_required
def admin_route():
    return jsonify({'message': 'Admin route'})
```

## Required User Service APIs

Auth service communicates with the user service for user management. The following internal APIs must be implemented in the user service:

### POST /internal/users
Create a new user account.

**Request Body:**
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "user@example.com",
  "password": "$2b$12$hashed_password_string..."
}
```

**Note:** The password is already hashed using bcrypt by auth-service before sending to user-service.

**Response (201 Created):**
```json
{
  "userId": "uuid-string",
  "firstName": "John",
  "lastName": "Doe",
  "email": "user@example.com"
}
```

**Response (409 Conflict):**
```json
{
  "error": "User with this email already exists"
}
```

### POST /internal/users/verify
Verify user credentials (email and password).

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Note:** The password is sent in plain text. User service should hash it and compare with stored hash.

**Response (200 OK):**
```json
{
  "userId": "uuid-string",
  "userType": "normal_user",
  "isActive": true
}
```

**Response (401 Unauthorized):**
```json
{
  "error": "Invalid email or password"
}
```

**Response (404 Not Found):**
```json
{
  "error": "User not found"
}
```

## Configuration

Environment variables:
- `JWT_SECRET_KEY`: Secret key for JWT token signing (required, no default)
- `USER_SERVICE_URL`: URL of the user-service (default: 'http://user-service:5000')
- `RABBITMQ_HOST`: RabbitMQ host (default: 'rabbitmq')
- `RABBITMQ_PORT`: RabbitMQ port (default: '5672')
- `RABBITMQ_USER`: RabbitMQ username (default: 'guest')
- `RABBITMQ_PASSWORD`: RabbitMQ password (default: 'guest')
- `EMAIL_QUEUE`: Email queue name (default: 'email_queue')

## Dependencies

- Flask 3.0.0
- Requests 2.31.0
- Pika 1.3.2 (RabbitMQ client)
- Python-dotenv 1.0.0
- bcrypt 4.1.2 (Password hashing)
- pyjwt 2.8.0 (JWT token generation and verification)

## Running the Service

```bash
# Install dependencies
pip install -r requirements.txt

# Set required environment variables
export JWT_SECRET_KEY=your-secret-key-here

# Run the service
python run.py
```

The service will run on `http://localhost:5000` by default.

## Docker

```bash
# Build the image
docker build -t auth-service .

# Run the container
docker run -p 5000:5000 -e JWT_SECRET_KEY=your-secret-key-here auth-service
```
