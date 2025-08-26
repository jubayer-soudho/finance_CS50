# finance_CS50
CS50x Finance — Stock Trading Web App (Flask + SQLite) A Flask &amp; SQLite app where users can register, log in, and simulate stock trading. Features: stock quote lookup, buy/sell shares, portfolio view, transaction history, password change, and add cash. Implements CS50 Finance problem set with enhancements.

## Features

- User registration and login
- Stock quote lookup (real-time prices)
- Buy and sell shares
- View current portfolio and cash balance
- Transaction history
- Add cash to account
- Change password
- Apology page for error handling

## Technologies

- Python (Flask)
- SQLite (via CS50 library)
- HTML/CSS (Jinja templates)
- Flask-Session for user sessions

## Setup

1. **Clone the repository:**
	```
	git clone https://github.com/jubayer-soudho/finance_CS50.git
	cd finance_CS50
	```

2. **Install dependencies:**
	```
	pip install -r requirements.txt
	```

3. **Set up the database:**
	- The `finance.db` file is included. If you need to reset, delete it and restart the app.

4. **Run the app:**
	```
	flask run
	```
	- By default, the app runs on `http://127.0.0.1:5000/`.

## Usage

- Register a new account.
- Log in to access your dashboard.
- Use the navigation bar to quote stocks, buy/sell, view history, add cash, or change password.

## File Structure

- `app.py`: Main Flask application
- `helpers.py`: Utility functions and decorators
- `finance.db`: SQLite database
- `requirements.txt`: Python dependencies
- `static/`: CSS and images
- `templates/`: HTML templates

## License

See `LICENSE` for details.
