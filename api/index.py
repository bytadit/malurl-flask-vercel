import torch
from transformers import pipeline
from transformers import AutoTokenizer
from transformers import AutoModelForSequenceClassification
from flask import Flask, request, jsonify

device = torch.device("cpu")  # Use CPU device

def predictNewData(link):
    checkpoint = 'bgspaditya/malurl-electra-10e'
    id2label = {0:'benign',1:'defacement',2:'malware',3:'phishing'}
    label2id = {'benign':0,'defacement':1,'malware':2,'phishing':3}
    num_labels=4
    tokenizer = AutoTokenizer.from_pretrained(checkpoint, use_fast=True)
    model = AutoModelForSequenceClassification.from_pretrained(checkpoint, num_labels=num_labels, id2label=id2label, label2id=label2id)
    url_classifier = pipeline(task='text-classification', model=model, tokenizer=tokenizer, device=device)
    result = url_classifier(link)
    return {'label': result[0]['label'], 'score': result[0]['score']}

app = Flask(__name__)

@app.route('/')
def api_home():
    return jsonify({"greeting": "Welcome to Malicious URL Detection using ELECTRA Api!"})

@app.route('/predict', methods=['POST'])
def predict_url():
    data = request.json
    text = data['text']
    prediction = predictNewData(text)
    return jsonify(prediction)

if __name__ == '__main__':
    app.run(debug=True)
