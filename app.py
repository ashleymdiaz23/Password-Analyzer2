from flask import Flask, render_template, request, jsonify
import os
import sys
import hashlib
import requests

app = Flask(__name__)

# Project root = Password Analyzer 2
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from analyzer import analyze_password


def load_common_passwords():
    path = os.path.join(PROJECT_ROOT, "common_passwords.txt")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def get_pwned_count(password: str) -> int:
    """
    Check password against Have I Been Pwned Pwned Passwords API
    using k-anonymity. Returns number of times seen in breach data.
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "User-Agent": "PasswordAnalyzerProject/1.0",
        "Add-Padding": "true"
    }

    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()

    hashes = response.text.splitlines()
    for line in hashes:
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    password = (data.get("password") or "").strip()

    if not password:
        return jsonify({"error": "Password cannot be empty"}), 400

    common_passwords = load_common_passwords()
    result = analyze_password(password, common_passwords)

    score = 100
    score -= len(result["issues"]) * 15
    if len(password) < 12:
        score -= 10
    score = max(0, min(100, score))

    try:
        breach_count = get_pwned_count(password)
    except Exception:
        breach_count = -1  # means check failed

    return jsonify({
        "score": score,
        "strength": result["strength"],
        "issues": result["issues"],
        "breach_count": breach_count
    })


if __name__ == "__main__":
    app.run(debug=True)