# Auth Service

Auth Service is a Flask-based microservice that handles user authentication for the Forum Project.

## Features

- **User Registration**: POST `/auth/register` - Register new users

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

**Note:** Password will be hashed by user-service before storing in database. Email verification will be handled separately in user profile or other services.

## Configuration

Environment variables:
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

## Running the Service

```bash
# Install dependencies
pip install -r requirements.txt

# Run the service
python run.py
```

The service will run on `http://localhost:5000` by default.

## Docker

```bash
# Build the image
docker build -t auth-service .

# Run the container
docker run -p 5000:5000 auth-service
```
