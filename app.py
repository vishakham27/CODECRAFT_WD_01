
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)

# Development secret key; configure a strong environment secret before deployment
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this-key")

DATABASE = "users.db"


# Connect to the SQLite database
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# Create the users table
def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        """)


# Home page
@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# Registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Please fill in all fields.")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        try:
            with get_db() as conn:
                cursor = conn.execute(
                    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                    (name, email, password_hash)
                )
                user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            flash("An account with this email already exists.")
            return render_template("register.html")

        session.clear()
        session["user_id"] = user_id
        session["name"] = name

        return redirect(url_for("dashboard"))

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")


# Protected dashboard
@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        flash("Please log in to access the dashboard.")
        return redirect(url_for("login"))

    response = app.make_response(
        render_template("dashboard.html", name=session["name"])
    )
    response.headers["Cache-Control"] = "no-store"
    return response


# Logout
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    response = app.make_response(redirect(url_for("login")))
    response.headers["Cache-Control"] = "no-store"
    flash("You have been logged out.")
    return response


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
