from flask import Flask, render_template_string, redirect, request, render_template

app = Flask(__name__)

# ruleid: python.flask.security.debug-true
app.run(host="0.0.0.0", debug=True)

@app.route("/greet")
def greet():
    name = request.args.get("name")
    # ruleid: python.flask.security.render-template-string
    return render_template_string(f"<h1>Hello {name}</h1>")

@app.route("/login")
def login():
    # ruleid: python.flask.security.open-redirect
    return redirect(request.args.get("next"))

# ok: python.flask.security.debug-true
app.run(host="0.0.0.0", debug=False)

# ok: python.flask.security.render-template-string
@app.route("/safe-greet")
def safe_greet():
    return render_template("greet.html", name=request.args.get("name"))
