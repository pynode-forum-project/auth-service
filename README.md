# Auth Service

Auth Service is a Flask-based microservice that handles user authentication for the Forum Project.

## Features

- **User Registration**: POST `/auth/register` - Register new users
- **User Login**: POST `/auth/login` - Verify credentials and generate JWT tokens

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
- pyjwt 2.8.0 (JWT token generation)

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
