import os, sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "amazon-local-demo-change-this")
DB = os.path.join(app.root_path, "instance", "amazon.db")
os.makedirs(os.path.dirname(DB), exist_ok=True)

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            referral_code TEXT UNIQUE NOT NULL
        )""")
init_db()

def logged_in():
    return bool(session.get("user_id"))

@app.route("/")
def home():
    if not logged_in():
        return redirect(url_for("auth"))
    return render_template("home.html", active="home")

@app.route("/auth", methods=["GET", "POST"])
def auth():
    mode = request.args.get("mode", "signin")
    if request.method == "POST":
        mode = request.form.get("mode", "signin")
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if mode == "signup":
            confirm = request.form.get("confirm_password", "")
            referral = request.form.get("referral_code", "").strip()
            if not email or len(password) < 8 or password != confirm:
                flash("Enter a valid email and matching password of at least 8 characters.")
                return render_template("auth.html", mode=mode)
            try:
                with db() as con:
                    cur = con.execute("INSERT INTO users(email,password_hash,referral_code) VALUES(?,?,?)",
                                      (email, generate_password_hash(password), os.urandom(3).hex().upper()))
                    user_id = cur.lastrowid
                session["user_id"] = user_id
                session["email"] = email
                flash("Registration successful!")
                return redirect(url_for("home"))
            except sqlite3.IntegrityError:
                flash("That email is already registered.")
        else:
            with db() as con:
                user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session["user_id"] = user["id"]
                session["email"] = email
                return redirect(url_for("home"))
            flash("Email or password is incorrect.")
    return render_template("auth.html", mode=mode)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth"))

@app.route("/my")
def my():
    if not logged_in(): return redirect(url_for("auth"))
    with db() as con:
        user = con.execute("SELECT referral_code FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return render_template("my.html", active="my", referral=user["referral_code"] if user else "")

@app.route("/ai")
def ai():
    if not logged_in(): return redirect(url_for("auth"))
    series = request.args.get("series", "B")
    if series not in ("B", "F", "W"): series = "B"
    return render_template("ai.html", active="ai", series=series)

@app.route("/team")
def team():
    if not logged_in(): return redirect(url_for("auth"))
    with db() as con:
        user = con.execute("SELECT referral_code FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return render_template("team.html", active="team", referral=user["referral_code"] if user else "")

@app.route("/income")
def income():
    if not logged_in(): return redirect(url_for("auth"))
    return render_template("income.html", active="income")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
