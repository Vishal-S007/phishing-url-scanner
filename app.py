"""
app.py
------
Tiny Flask server. Two routes:
  GET  /          -> the page
  POST /api/scan  -> takes {"url": "..."}, returns the analysis JSON
"""

from flask import Flask, render_template, request, jsonify
from detector import analyze

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not url.strip():
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(analyze(url))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
