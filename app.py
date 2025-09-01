# app.py (Final Dashboard Version)
import os
import shutil
from flask import Flask, request, jsonify, render_template
from static_analyzer import decompile_apk, analyze_manifest, find_urls
from dynamic_analyzer import run_dynamic_analysis
from threat_scorer import calculate_threat_score

# --- Initial Setup ---
os.makedirs('uploads', exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    # --- File Handling ---
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '' or not file.filename.endswith('.apk'):
        return jsonify({'error': 'Invalid file. Please upload an APK.'}), 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    
    output_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'decompiled_' + os.path.splitext(file.filename)[0])
    
    # --- Stage 1: Static Analysis ---
    static_results = {}
    if decompile_apk(filepath, output_dir):
        static_results["permissions"] = analyze_manifest(output_dir)
        static_results["urls"] = find_urls(output_dir)
        shutil.rmtree(output_dir, ignore_errors=True)
    else:
        static_results["error"] = "Failed to decompile APK."

    # --- Stage 2: Dynamic Analysis ---
    dynamic_results = run_dynamic_analysis(filepath)

    # --- Stage 3: AI Threat Scoring ---
    score, detailed_findings = calculate_threat_score(static_results, dynamic_results)

    # --- Final JSON Response (Updated for Dashboard) ---
    final_results = {
        "status": "success",
        "filename": file.filename,
        "threat_score": score,
        "detailed_findings": detailed_findings,
        "static_urls": static_results.get("urls", [])
    }
    
    return jsonify(final_results)

# --- Server Start ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)