from datetime import datetime, timedelta, timezone
import jwt
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
JWT_SECRET = "change-this-jwt-secret"

db.init_app(app)
with app.app_context():
    db.create_all()

def create_token(user):
    payload = {
        "user_id": user.id,
        "email": user.email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=2)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "Bearer token required"}), 401
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            user = db.session.get(User, data["user_id"])
            if not user:
                raise ValueError
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, ValueError):
            return jsonify({"error": "Invalid or expired token"}), 401
        return fn(user, *args, **kwargs)
    return wrapper

@app.route("/")
def home():
    return render_template("home.html", user=session.get("user"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or len(password) < 6:
            flash("Name, valid email and password of 6+ characters are required.", "error")
            return render_template("register.html")

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
            return render_template("register.html")

        user = User(name=name, email=email, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid email or password.", "error")
            return render_template("login.html")

        session["user"] = {"id": user.id, "name": user.name, "email": user.email}
        session["jwt"] = create_token(user)
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"], token=session["jwt"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.get("/api/me")
@token_required
def me(user):
    return jsonify({"id": user.id, "name": user.name, "email": user.email})

if __name__ == "__main__":
    app.run(debug=True)
