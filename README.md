# Secure Flask App

A secure web application built with Flask, implementing best security practices to protect against common vulnerabilities.

## Features
- User authentication and authorization
- Secure session management
- Protection against SQL Injection, XSS, and CSRF attacks
- Secure password hashing
- Logging and monitoring
- API security best practices

## Installation

### Prerequisites
- Python 3.x
- Flask
- Virtual Environment (recommended)

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/nadarallen/secure-flask-app.git
   cd secure-flask-app
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set environment variables (for development):
   ```bash
   export FLASK_APP=app.py
   export FLASK_ENV=development
   ```
   On Windows (cmd):
   ```cmd
   set FLASK_APP=app.py
   set FLASK_ENV=development
   ```
5. Run the application:
   ```bash
   flask run
   ```

## Security Features Implemented
- **Input Validation:** Prevents SQL Injection and XSS attacks.
- **CSRF Protection:** Implements CSRF tokens for secure form submissions.
- **Secure Authentication:** Uses hashed passwords and session management.
- **Logging and Monitoring:** Keeps track of authentication attempts and errors.

## Folder Structure
```
secure-flask-app/
│── app.py          # Main application file
│── config.py       # Configuration settings
│── requirements.txt  # Dependencies
│── static/         # Static files (CSS, JS, images)
│── templates/      # HTML templates
│── models.py       # Database models
│── routes.py       # Application routes
└── utils/          # Helper functions
```

## Contributing
Contributions are welcome! Feel free to fork this repository, make improvements, and submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contact
For any inquiries or contributions, reach out to [Allen](https://github.com/nadarallen).

