# Python Backend Example (Flask) , Accepts /analyze POST and returns phishing status

from flask import Flask, request, jsonify
from phishingDetector import analyzeEmail

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    result = analyzeEmail(data['emailContent'], data['subject'], data['from'])
    return jsonify(result)

app.run(port=5000)
