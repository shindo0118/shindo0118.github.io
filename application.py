import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""
    # Find out users current cash amount
    current = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    # Find out users current share amount
    shares = db.execute("SELECT symbol, SUM(shares) FROM transactions WHERE username = ? GROUP BY symbol", session["user_id"])

    # Create a list to contain the lookup for-loop result
    mylists = []

    # look up the current share price for all of the symbols that the user have
    for share in shares:
        mylists.append(lookup(share["symbol"]))

    # if-statement for users using add money function
    if request.method == "POST":
        # Allow the user to add money and update the database
        add = request.form.get("add")
        db.execute("UPDATE users SET cash = cash + ?", add)
        # Update the "current" variable
        current = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    # render the index using the gained information
    return render_template("index.html", current=current, shares=shares, mylists=mylists)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Store the variable user entered in the form
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Ensure that the symbol matches with the database
        if not lookup(symbol):
            return apology("invalid stock symbol", 400)

        # Lookup the stock price for the entered symbol
        quoted = lookup(symbol)["price"]

        # Get the amount of cash that user currently has
        current = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        # Ensure that the entered number for share is positive integer
        if not shares.isdecimal() or not float(shares) > 0:
            return apology("invalid stock purchase request", 400)

        # Ensure there is enough money to purchase the stocks
        elif int(quoted)*int(shares) > int(current):
            return apology("Not enough money for the purchase", 400)

        # Reduce the amount of money used for the purchase
        db.execute("UPDATE users SET cash = cash - ?", int(quoted)*int(shares))

        # Record the transaction
        db.execute("INSERT INTO transactions (username, symbol, shares, price) VALUES (?, ?, ?, ?)",
                   session["user_id"], symbol.upper(), shares, quoted)
        return redirect("/")
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Get all the transaction information from the transactions database
    transactions = db.execute("SELECT * FROM transactions WHERE username = ?", session["user_id"])
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
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

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
    """Get stock quote."""

    # Quote the stock when user request information through POST
    if request.method == "POST":

        # Look up the information and return error if no match
        symbol = request.form.get("symbol")
        if not lookup(symbol):
            return apology("no match", 400)
        return render_template("quote.html", quotes=lookup(symbol))

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Get the information submitted by the user
        name = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure username doesn't exist
        elif db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username")):
            return apology("username already exists", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password and confirmation match
        elif not password == confirmation:
            return apology("password must match", 400)

        # Register to database if there is no problem
        else:
            hashed = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", name, hashed)
            return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    dbsymbols = db.execute("SELECT symbol FROM transactions WHERE username = ? GROUP BY symbol", session["user_id"])

    if request.method == "POST":
        # Get the information submitted by the user
        sellshares = request.form.get("shares")
        sellsymbol = request.form.get("symbol")

        # Get the total amount of the share that user is going to sell
        dbshares = db.execute("SELECT SUM(shares) FROM transactions WHERE username = ? AND symbol = ?",
                              session["user_id"], sellsymbol)[0]["SUM(shares)"]

        # Lookup the stock price for the entered symbol
        quoted = lookup(sellsymbol)["price"]

        # Ensure that the symbol matches with the database
        if not quoted:
            return apology("invalid stock symbol", 400)

        # Check whether user have enough amount of share to sell
        if int(dbshares) < int(sellshares):
            return apology("You don't have enough shares to sell", 400)

        # Register the transaction to with minus number of shares sold
        db.execute("INSERT INTO transactions (username, symbol, shares, price) VALUES (?, ?, ?, ?)",
                   session["user_id"], sellsymbol.upper(), -int(sellshares), quoted)

        # Increase the amount of cash by selling shares
        db.execute("UPDATE users SET cash = cash + ?", int(quoted)*int(sellshares))

        return redirect("/")

    return render_template("sell.html", symbols=dbsymbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
