# phishing_app.py
from flask import Flask, request, render_template_string
import pandas as pd
import tldextract
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import re

# ------------------ Load Dataset & Train ML ------------------
data = pd.read_csv("phishing_safe_dataset.csv")  # CSV must have 'text' and 'label' columns
vectorizer = TfidfVectorizer(lowercase=True, stop_words='english')
X = vectorizer.fit_transform(data['text'])
y = data['label']

model = LogisticRegression()
model.fit(X, y)

# ------------------ Feature Extraction & Rule-based Checks ------------------
def extract_features(url):
    ext = tldextract.extract(url)
    features = {
        "has_https": url.startswith("https"),
        "num_dots": url.count('.'),
        "domain_length": len(ext.domain),
        "has_ip": bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url)),
        "has_suspicious_tld": ext.suffix in ["xyz", "top", "ru"],
        "has_email": bool(re.search(r'\S+@\S+', url)),
        "has_long_path": len(url.split('/')) > 5,
        "has_digits": any(char.isdigit() for char in url),
        "has_suspicious_keywords": any(word in url.lower() for word in ["login", "verify", "secure", "account", "refund"]),
    }
    return features

def levenshtein(a, b):
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    previous_row = range(len(b) + 1)
    for i, c1 in enumerate(a):
        current_row = [i + 1]
        for j, c2 in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def brand_similarity_check(url):
    brands = ["paypal", "google", "amazon", "microsoft", "apple", "facebook"]
    ext = tldextract.extract(url)
    domain = ext.domain.lower()
    for brand in brands:
        if 0 < levenshtein(domain, brand) <= 2:
            return f"Domain '{domain}' is similar to brand '{brand}'"
    return None

def check_rules(url):
    reasons = []
    features = extract_features(url)
    if not features["has_https"]:
        reasons.append("No HTTPS")
    if features["has_ip"]:
        reasons.append("IP address used in URL")
    if features["has_suspicious_tld"]:
        reasons.append("Suspicious TLD")
    if features["has_email"]:
        reasons.append("Email address in URL")
    if features["has_long_path"]:
        reasons.append("Long/complex URL path")
    if features["domain_length"] < 3:
        reasons.append("Very short domain")
    if features["has_digits"]:
        reasons.append("Digits in domain/path")
    if features["has_suspicious_keywords"]:
        reasons.append("Suspicious keyword detected")
    brand_alert = brand_similarity_check(url)
    if brand_alert:
        reasons.append(brand_alert)
    return reasons

def analyze_url(url):
    ml_pred = model.predict(vectorizer.transform([url]))[0]
    ml_conf = model.predict_proba(vectorizer.transform([url]))[0].max()
    rules = check_rules(url)
    # Mark as phishing if ML or rules flag it
    phishing_flag = ml_pred == 1 or len(rules) > 0
    return {
        "ML Prediction": int(phishing_flag),
        "Confidence": f"{ml_conf*100:.1f}%",
        "Rule Alerts": rules
    }

# ------------------ Flask Web App ------------------
app = Flask(__name__)

html = '''
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
<div class="container mt-5">
  <h2>🔎 Phishing Detector</h2>
  <form method="POST" class="mb-4">
    <div class="input-group">
      <input name="text" class="form-control" placeholder="Enter URL or text..." required value="{{ input_text|default('') }}">
      <button class="btn btn-primary" type="submit">Check</button>
    </div>
  </form>
  {% if result %}
    <div class="card p-3 mb-3 {% if result['ML Prediction']==1 %}border-danger{% else %}border-success{% endif %}">
      <h4>
        {% if result['ML Prediction']==1 %}
          <span class="text-danger">❌ Phishing Detected!</span>
        {% else %}
          <span class="text-success">✅ Safe</span>
        {% endif %}
      </h4>
      <p><strong>Confidence:</strong> 
        <span class="badge bg-info">{{result['Confidence']}}</span>
      </p>
      {% if result['Rule Alerts'] %}
        <p><strong>Why flagged?</strong></p>
        <ul>
          {% for alert in result['Rule Alerts'] %}
            <li class="text-warning">{{alert}}</li>
          {% endfor %}
        </ul>
      {% endif %}
    </div>
  {% endif %}
  <div class="alert alert-secondary">
    <strong>Tips:</strong> Never click suspicious links. Check for HTTPS, strange domains, and spelling errors!
  </div>
</div>
'''

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    input_text = ""
    if request.method == "POST":
        input_text = request.form["text"]
        result = analyze_url(input_text)
    return render_template_string(html, result=result, input_text=input_text)

if __name__ == "__main__":
    app.run(debug=True)