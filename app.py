from ioc_export import export_iocs_csv, export_iocs_json
from database import init_db, save_analysis, get_history
from flask import Flask, render_template, request, send_file
from analyzer import parse_email_header
from pdf_report import create_pdf

app = Flask(__name__)
init_db()


@app.route("/")
def home():
    return render_template(
        "index.html",
        results=None
    )


@app.route("/upload", methods=["POST"])
def upload():

    file = request.files["email_file"]

    content = file.read().decode("utf-8", errors="ignore")

    results = parse_email_header(content)

    save_analysis(results)

    create_pdf(results)
    
    export_iocs_csv(results["IOCs"])
    export_iocs_json(results["IOCs"])

    return render_template(
        "index.html",
        results=results
    )


@app.route("/download")
def download():

    return send_file(
        "report.pdf",
        as_attachment=True
    )

@app.route("/download_ioc_csv")
def download_ioc_csv():

    return send_file(
        "iocs.csv",
        as_attachment=True
    )


@app.route("/download_ioc_json")
def download_ioc_json():

    return send_file(
        "iocs.json",
        as_attachment=True
    )

# -------------------------------
# HISTORY PAGE
# -------------------------------

@app.route("/history")
def history():

    history = get_history()

    return render_template(
        "history.html",
        history=history
    )


# -------------------------------
# START SERVER
# -------------------------------

if __name__ == "__main__":
    app.run(debug=True)
