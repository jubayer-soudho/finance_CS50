import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get user's stock holdings: sum of shares per symbol
    rows = db.execute("""
        SELECT symbol, SUM(shares) as total_shares
        FROM transactions
        WHERE user_id = ?
        GROUP BY symbol
        HAVING total_shares > 0
    """, session["user_id"])

    holdings = []
    total_stock_value = 0

    for row in rows:
        symbol = row["symbol"]
        shares = row["total_shares"]
        quote = lookup(symbol)
        if quote:
            price = quote["price"]
            total = shares * price
            total_stock_value += total

            holdings.append({
                "symbol": symbol,
                "name": quote["name"],
                "shares": shares,
                "price": usd(price),
                "total": usd(total)
            })

    # Get user's cash
    cash_row = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = cash_row[0]["cash"]
    grand_total = total_stock_value + cash

    return render_template("index.html", holdings=holdings, cash=usd(cash), grand_total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Validate symbol
        if not symbol:
            return apology("Must provide symbol", 400)
        stock = lookup(symbol.upper())
        if not stock:
            return apology("Invalid symbol", 400)

        # Validate shares
        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("Shares must be a positive integer", 400)
        shares = int(shares)

        # Check user's cash
        user_id = session["user_id"]
        rows = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        cash = rows[0]["cash"]

        total_price = stock["price"] * shares

        # Check if user can afford
        if total_price > cash:
            return apology("Not enough cash", 400)

        # Record transaction
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            user_id,
            stock["symbol"].upper(),
            shares,
            stock["price"]
        )

        # Update user's cash
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_price, user_id)

        # Redirect to homepage
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("""
        SELECT symbol, shares, price, transacted
        FROM transactions
        WHERE user_id = ?
        ORDER BY transacted DESC
    """, session["user_id"])

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("must provide symbol")

        stock = lookup(symbol.upper())
        if stock is None:
            return apology("invalid symbol")

        return render_template("quoted.html", stock=stock)

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check for missing fields
        if not username:
            return apology("must provide username", 400)
        elif not password:
            return apology("must provide password", 400)
        elif not confirmation:
            return apology("must confirm password", 400)
        elif password != confirmation:
            return apology("passwords do not match", 400)

        # Hash the password
        hash_pw = generate_password_hash(password)

        # Try inserting the user
        try:
            user_id = db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)",
                username,
                hash_pw
            )
        except ValueError:
            return apology("username already exists", 400)

        # Log the user in
        session["user_id"] = user_id

        # Redirect to homepage
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    user_id = session["user_id"]

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Validate inputs
        if not symbol:
            return apology("Must provide symbol", 400)
        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("Shares must be a positive integer", 400)
        shares = int(shares)

        # Check how many shares the user owns
        rows = db.execute("""
            SELECT SUM(shares) as total_shares
            FROM transactions
            WHERE user_id = ? AND symbol = ?
        """, user_id, symbol.upper())

        total_shares = rows[0]["total_shares"]
        if total_shares is None or total_shares < shares:
            return apology("Too many shares", 400)

        # Look up current price
        stock = lookup(symbol.upper())
        if not stock:
            return apology("Invalid symbol", 400)

        # Calculate total value of sale
        total_price = stock["price"] * shares

        # Record transaction (as negative shares)
        db.execute("""
            INSERT INTO transactions (user_id, symbol, shares, price)
            VALUES (?, ?, ?, ?)
        """, user_id, symbol.upper(), -shares, stock["price"])

        # Update user's cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total_price, user_id)

        return redirect("/")

    else:
        # Show symbols the user owns (only positive total shares)
        rows = db.execute("""
            SELECT symbol
            FROM transactions
            WHERE user_id = ?
            GROUP BY symbol
            HAVING SUM(shares) > 0
        """, user_id)

        symbols = [row["symbol"] for row in rows]
        return render_template("sell.html", symbols=symbols)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current")
        new = request.form.get("new")
        confirm = request.form.get("confirm")

        # Validate inputs
        if not current or not new or not confirm:
            return apology("All fields are required")

        if new != confirm:
            return apology("New passwords do not match")

        # Get current password hash
        row = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]

        if not check_password_hash(row["hash"], current):
            return apology("Incorrect current password")

        # Update password
        hash_new = generate_password_hash(new)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hash_new, session["user_id"])

        flash("Password changed successfully!")
        return redirect("/")

    return render_template("change_password.html")


@app.route("/add-cash", methods=["GET", "POST"])
@login_required
def add_cash():
    if request.method == "POST":
        amount = request.form.get("amount")

        # Validate amount
        try:
            amount = float(amount)
            if amount <= 0:
                raise ValueError
        except:
            return apology("Enter a positive amount")

        # Update cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", amount, session["user_id"])
        flash(f"${amount:.2f} added to your account!")
        return redirect("/")

    return render_template("add_cash.html")
