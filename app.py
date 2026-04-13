from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3

app = Flask(__name__)
CORS(app)

# 📦 CREATE DATABASE
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# 🆕 SIGNUP
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    email = data["email"]
    password = data["password"]

    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
        conn.commit()
        conn.close()
        return jsonify({"message": "User created"})
    except:
        return jsonify({"error": "User already exists"}), 400

# 🔐 LOGIN
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data["email"]
    password = data["password"]

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
    user = c.fetchone()
    conn.close()

    if user:
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"error": "Invalid credentials"}), 401


# 🛍 PRODUCTS (🔥 ADD THIS)
@app.route("/products", methods=["GET"])
def get_products():
    return jsonify([
        {
            "name": "Football",
            "price": 999,
            "category": "Football",
            "image": "https://via.placeholder.com/300"
        },
        {
            "name": "Cricket Bat",
            "price": 1999,
            "category": "Cricket",
            "image": "https://via.placeholder.com/300"
        }
    ])


# 🚀 RUN SERVER (ALWAYS LAST)
if __name__ == "__main__":
    app.run(debug=True)