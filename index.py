from flask import Flask, request, jsonify
import joblib
from preprocess import preProcess

app = Flask(__name__)

def predictNewData(url):
    try:
        model = joblib.load('resource\RandomForest.joblib')
        preprocessed_text = preProcess(url)
        input_prediction = model.predict(preprocessed_text)
        probability_estimates = model.predict_proba(preprocessed_text)
        probability_phishing = probability_estimates[0][1]
        prediction = "Phishing" if input_prediction == 1 else "Benign"
        return {"prediction": prediction, "probability": probability_phishing}
    except Exception as e:
        return {"error": str(e)}

@app.route('/')
def api_home():
    return jsonify({"greeting": "Welcome to Malicious URL Detection using ELECTRA Api!"})

@app.route('/predict', methods=['POST'])
def predict_url():
    data = request.json
    url = data.get('url', '')
    if not url:
        return jsonify({"error": "URL not provided"})
    prediction = predictNewData(url)
    return jsonify(prediction)

if __name__ == '__main__':
    app.run(debug=True)
