from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def index():
    return """
    <h2>Login</h2>
    <form method="POST" action="/login">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Login">
    </form>
    <h2>Search</h2>
    <form method="GET" action="/search">
        Search: <input name="q">
        <input type="submit" value="Search">
    </form>
    """

# INTENTIONALLY VULNERABLE — for demo only
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    # Vulnerable: reflects input without sanitization
    return f"<p>Welcome, {username}!</p>"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Vulnerable: reflects input — XSS possible
    return f"<p>Results for: {q}</p>"

if __name__ == "__main__":
    app.run(debug=True)