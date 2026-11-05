from flask import Flask, render_template, request
from detector import analyze_email, analyze_url

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    kind = "email"
    if request.method == "POST":
        kind = request.form.get("kind", "email")
        if kind == "url":
            result = analyze_url(request.form.get("url", ""))
        else:
            result = analyze_email(
                request.form.get("sender", ""),
                request.form.get("subject", ""),
                request.form.get("body", "")
            )
    return render_template("index.html", result=result, kind=kind)

@app.route("/about")
def about():
    return render_template("about.html")

if __name__ == "__main__":
    # Local-only development server. Do not expose this demo to the public internet.
    app.run(host="127.0.0.1", port=5000, debug=True)
