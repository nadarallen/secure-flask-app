# Secure Flask App

A secure, modern web application built with Flask, implementing best security practices and a premium user interface.

## 🚀 Features

### Security

- **User Authentication**: Secure session management using `Flask-Login`.
- **Password Hashing**: Industry-standard `bcrypt` hashing for password storage.
- **Form Security**: CSRF protection and strict validation using `Flask-WTF`.
- **SQL Injection Protection**: Uses `Flask-SQLAlchemy` ORM to prevent SQL injection.
- **Secure Configuration**: Environment variables for sensitive data using `python-dotenv`.

### User Interface

- **Modern Design**: Built with **Tailwind CSS** for a clean, responsive, and premium look.
- **User Experience**: Flash messages for feedback, smooth transitions, and intuitive layouts.

## 🛠️ Tech Stack

- **Backend**: Flask, Flask-SQLAlchemy, Flask-Login, Flask-WTF, Flask-Bcrypt
- **Frontend**: HTML5, Tailwind CSS (via CDN)
- **Database**: SQLite (Development), easy upgrade to PostgreSQL

## 📂 Project Structure

```
secure-flask-app/
│── app.py           # Application entry point & factory
│── config.py        # Configuration settings
│── models.py        # Database models (User)
│── forms.py         # WTForms implementation
│── routes.py        # Route logic & authentication
│── requirements.txt # Project dependencies
│── .env             # Environment variables (git-ignored)
│── templates/       # HTML Templates (Login, Signup, Dashboard)
│── static/          # Static assets
└── instance/        # Database storage (created on run)
```

## ⚡ Installation & Setup

1. **Clone the repository:**

    ```bash
    git clone https://github.com/nadarallen/secure-flask-app.git
    cd secure-flask-app
    ```

2. **Create a Virtual Environment:**

    ```bash
    python -m venv venv
    
    # Windows
    venv\Scripts\activate
    
    # macOS/Linux
    source venv/bin/activate
    ```

3. **Install Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4. **Set Environment Variables:**
    Create a `.env` file in the root directory:

    ```env
    SECRET_KEY=your_secure_random_key
    DATABASE_URL=sqlite:///users.db
    ```

5. **Run the Application:**

    ```bash
    flask run
    ```

    Access the app at `http://127.0.0.1:5000`.

## 🛡️ API & Security Details

- **Input Validation**: Strict regex patterns for usernames and passwords.
- **Session Security**: HTTPOnly cookies (default Flask behavior) and session fix protection.

## 🤝 Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## 📄 License

MIT License.
