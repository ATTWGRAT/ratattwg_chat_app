# Flask SQLAlchemy Application

A well-structured Flask application with SQLAlchemy ORM and SQLite3 database.

## 📁 Project Structure

```
backend/
├── app/
│   ├── __init__.py          # Application factory
│   ├── models.py            # Database models
│   ├── routes.py            # API routes and endpoints
│   └── templates/
│       └── index.html       # Home page template
├── instance/                 # Instance folder (created automatically)
│   └── app.db               # SQLite database (created after init)
├── config.py                # Configuration settings
├── run.py                   # Application entry point
├── requirements.txt         # Python dependencies
├── .env.example            # Environment variables example
├── .gitignore              # Git ignore rules
└── README.md               # This file
```

## 🚀 Quick Start

### 1. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Set up environment variables

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 4. Initialize the database

```bash
flask --app run.py init-db
```

### 5. (Optional) Seed with sample data

```bash
flask --app run.py seed-db
```

### 6. Run the application

```bash
python run.py
```

Visit `http://localhost:5000` in your browser.

## 📡 API Endpoints

### Users

- `GET /api/users` - Get all users
- `POST /api/users` - Create a new user
  ```json
  {
    "username": "john_doe",
    "email": "john@example.com"
  }
  ```
- `GET /api/users/<id>` - Get a specific user
- `DELETE /api/users/<id>` - Delete a user

### Posts

- `GET /api/posts` - Get all posts
- `POST /api/posts` - Create a new post
  ```json
  {
    "title": "My Post",
    "content": "Post content here",
    "user_id": 1
  }
  ```
- `GET /api/posts/<id>` - Get a specific post
- `PUT /api/posts/<id>` - Update a post
  ```json
  {
    "title": "Updated Title",
    "content": "Updated content"
  }
  ```
- `DELETE /api/posts/<id>` - Delete a post

## 🗄️ Database Models

### User

- `id` - Primary key
- `username` - Unique username
- `email` - Unique email address
- `created_at` - Timestamp
- `posts` - Relationship to Post model

### Post

- `id` - Primary key
- `title` - Post title
- `content` - Post content
- `user_id` - Foreign key to User
- `created_at` - Timestamp
- `updated_at` - Timestamp

## 🛠️ Development Commands

### Using Flask CLI

```bash
# Initialize database
flask --app run.py init-db

# Seed database with sample data
flask --app run.py seed-db

# Open Flask shell with context
flask --app run.py shell
```

### Database Migrations (with Flask-Migrate)

```bash
# Initialize migrations
flask --app run.py db init

# Create a migration
flask --app run.py db migrate -m "Description of changes"

# Apply migrations
flask --app run.py db upgrade
```

## 🔧 Configuration

The application supports multiple configurations:

- **Development** - Debug mode enabled
- **Production** - Optimized for production
- **Testing** - In-memory database for testing

Set the environment via `FLASK_ENV` variable in `.env` file.

## 📝 Notes

- The SQLite database is stored in `instance/app.db`
- The instance folder is automatically created on first run
- All database models use SQLAlchemy ORM
- The application uses the factory pattern for better testing and modularity

## 🤝 Contributing

Feel free to fork this project and make improvements!
