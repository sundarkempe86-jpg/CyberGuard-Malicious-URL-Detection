import os
import re
import requests
import joblib
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from readability import Document
import csv 

# Flask & Extensions
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

# --- 1. APP CONFIGURATION ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyberguard-secret-key-2025' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyberguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 

# --- 2. LOAD MACHINE LEARNING MODELS ---
try:
    rf_model = joblib.load("model/malicious_url_model.pkl")
    label_encoder = joblib.load("model/label_encoder.pkl")
    print("✅ ML Models Loaded Successfully")
except FileNotFoundError:
    print("⚠️ WARNING: Models not found. Please run 'train_advanced.py' first.")
    rf_model = None
    label_encoder = None

# --- 3. WHITELIST (Trusted Sites) ---
TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'yahoo.com', 'wikipedia.org',
    'zoom.us', 'live.com', 'reddit.com', 'netflix.com', 'microsoft.com', 'instagram.com',
    'bing.com', 'office.com', 'twitch.tv', 'linkedin.com', 'pinterest.com', 'apple.com',
    'github.com', 'stackoverflow.com', 'quora.com', 'adobe.com', 'whatsapp.com', 'dropbox.com',
    'bbc.com', 'cnn.com', 'nytimes.com', 'forbes.com', 'bloomberg.com', 'paypal.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'ebay.com', 'craigslist.org',
    'spotify.com', 'walmart.com', 'target.com', 'bestbuy.com', 'salesforce.com',
    'ibm.com', 'oracle.com', 'aws.amazon.com', 'imdb.com', 'weather.com', 'accuweather.com',
    'booking.com', 'tripadvisor.com', 'airbnb.com', 'expedia.com', 'aitchnu.com', 'gov.in',
    'nic.in', 'irctc.co.in'
}

# --- 4. DATABASE MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    scans = db.relationship('ScanHistory', backref='author', lazy=True)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    result = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    feedback = db.Column(db.String(50), default="None")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- 5. HELPER FUNCTIONS ---

def validate_url(url):
    """Ensures URL has http:// or https:// schema"""
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

def expand_short_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=2)
        return response.url
    except:
        return url

def extract_features(url):
    """
    Extracts features ensuring EXACT match with training columns.
    """
    features = {}
    
    # 1. Lexical Features
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['num_at'] = url.count('@')
    features['num_question'] = url.count('?')
    features['num_equal'] = url.count('=')
    features['num_digits'] = len(re.findall(r'\d', url))
    
    # 2. IP Address Check
    features['has_ip'] = int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url)))
    
    # 3. Subdomains
    features['num_subdomains'] = len(url.split('.')) - 2
    
    # 4. Suspicious Keywords
    suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'confirm', 'wallet', 'signin']
    features['has_suspicious_words'] = int(any(word in url.lower() for word in suspicious_keywords))
    
    # 5. HTTPS Check
    features['https'] = int('https' in url.lower())
    
    # Create DataFrame
    df = pd.DataFrame([features])
    
    return df

def get_prediction(url):
    # --- STEP 1: WHITELIST CHECK (Fast Pass) ---
    try:
        domain = urlparse(url).netloc.replace('www.', '')
        if domain in TRUSTED_DOMAINS or any(domain.endswith('.' + t) for t in TRUSTED_DOMAINS):
            return "benign", "Trusted Domain (Whitelist)"
    except:
        pass

    # --- STEP 2: HEURISTIC CHECK (Rule-Based Override) ---
    # Catches obvious phishing attempts that the ML model might miss
    
    # Rule A: IP Address URL
    if re.search(r'(\d{1,3}\.){3}\d{1,3}', url):
        return "malware", "Host is a raw IP address (High Risk)"
        
    # Rule B: Excessive Special Characters
    if url.count('@') > 0:
        return "phishing", "Contains '@' symbol (Email obfuscation)"
        
    # Rule C: Suspicious Keyword Combo (e.g., 'login' + 'update')
    suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'confirm']
    if any(word in url.lower() for word in suspicious_keywords) and len(url) > 70:
        return "phishing", "Suspicious keywords in long URL"

    # --- STEP 3: ML MODEL PREDICTION ---
    if rf_model and label_encoder:
        try:
            features = extract_features(url)
            
            # --- CRITICAL FIX: Reorder columns to match the loaded model ---
            # This prevents "Feature names must be in the same order" error
            if hasattr(rf_model, 'feature_names_in_'):
                features = features[rf_model.feature_names_in_]
            
            prediction = rf_model.predict(features)[0]
            result = label_encoder.inverse_transform([prediction])[0]
            
            # Explainability Logic
            reasons = []
            row = features.iloc[0]
            
            if 'has_ip' in row and row['has_ip'] == 1: reasons.append("Host is an IP address")
            if 'url_length' in row and row['url_length'] > 75: reasons.append("Abnormal URL length")
            if 'num_dots' in row and row['num_dots'] > 4: reasons.append("Excessive dot usage")
            if 'has_suspicious_words' in row and row['has_suspicious_words'] == 1: reasons.append("Suspicious security keywords found")
            if 'num_at' in row and row['num_at'] > 0: reasons.append("Contains '@' symbol")
            if 'num_subdomains' in row and row['num_subdomains'] > 2: reasons.append("Multiple subdomains hidden")
            
            if result == 'benign':
                reason = "No suspicious patterns detected."
            elif reasons:
                reason = " | ".join(reasons)
            else:
                reason = "Structural anomaly detected by AI"
            
            return result, reason
        except Exception as e:
            print(f"Prediction Error: {e}")
            return f"Error", f"System Error: {str(e)}"
    else:
        return "model_missing", "Model not loaded"

# --- 6. ROUTES ---

@app.route('/')
def home():
    definitions = {
        'Phishing': "Attempts to steal sensitive information like passwords and credit cards by pretending to be a trustworthy site.",
        'Malware': "Sites that download malicious software to damage your computer or gain unauthorized access.",
        'Defacement': "Legitimate websites that have been hacked and their content replaced by attackers.",
        'Benign': "Safe websites with no known threats detected."
    }
    return render_template('home.html', definitions=definitions)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Failed. Check credentials.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        try:
            new_user = User(username=username, email=email, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Username or Email already exists.', 'warning')
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_history = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.timestamp.desc()).all()
    total = len(user_history)
    malicious = len([x for x in user_history if x.result != 'benign'])
    return render_template('dashboard.html', history=user_history, total=total, malicious=malicious)

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    result = None
    url = None
    scan_id = None 
    reason = None
    definition = None
    
    threat_definitions = {
        'phishing': "This site mimics a legitimate service to steal your credentials.",
        'malware': "This site hosts dangerous software or exploits.",
        'defacement': "This site has been vandalized or hacked.",
        'benign': "This site appears safe to visit."
    }
    
    if request.method == 'POST':
        raw_url = request.form.get('url')
        if raw_url:
            # 1. Fix URL (Add http:// if missing)
            fixed_url = validate_url(raw_url)
            
            # 2. Expand Short URL
            final_url = expand_short_url(fixed_url)
            
            # 3. Predict (Get Result AND Reason)
            result, reason = get_prediction(final_url)
            
            # 4. Get Definition
            if result != "Error":
                definition = threat_definitions.get(result.lower(), "Unknown classification.")
            else:
                definition = "Could not classify due to internal error."
            
            # 5. Save to Database
            new_scan = ScanHistory(url=final_url, result=result, user_id=current_user.id)
            db.session.add(new_scan)
            db.session.commit()
            scan_id = new_scan.id 
        
    return render_template('scan.html', result=result, reason=reason, definition=definition, url=url, scan_id=scan_id)

@app.route('/feedback/<int:scan_id>/<string:feedback_type>')
@login_required
def feedback(scan_id, feedback_type):
    scan = ScanHistory.query.get_or_404(scan_id)
    
    if scan.author == current_user:
        scan.feedback = feedback_type
        db.session.commit()
        
        try:
            with open('feedback.csv', 'a', newline='') as f:
                writer = csv.writer(f)
                # Logic: If feedback is 'Incorrect' and result was 'phishing', assume 'benign'
                corrected_label = 'benign' if feedback_type == 'Incorrect' and scan.result != 'benign' else scan.result
                # If result was benign and feedback is incorrect, assume 'phishing' (safest bet)
                if feedback_type == 'Incorrect' and scan.result == 'benign':
                    corrected_label = 'phishing'
                
                writer.writerow([scan.url, corrected_label])
            flash('Feedback recorded! This data will be prioritized in the next training.', 'success')
        except Exception as e:
            flash(f"Error saving feedback: {e}", 'warning')
            
    return redirect(request.referrer or url_for('dashboard'))

# --- OLD FEATURES ---
@app.route('/scrape', methods=['GET', 'POST'])
@login_required
def scrape():
    results = []
    page_url = ""
    error_msg = None
    
    if request.method == 'POST':
        page_url = request.form.get("page_url")
        page_url = validate_url(page_url)
        
        try:
            # 1. Try to connect with a short timeout
            response = requests.get(page_url, timeout=5)
            
            # 2. Check if the page actually loaded (Status 200)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                links = [a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith('http')]
                
                if not links:
                    error_msg = "No links found on this page."
                
                # Limit to 10 links
                for link in links[:10]: 
                    pred, reason = get_prediction(link)
                    results.append({'url': link, 'result': pred})
            else:
                error_msg = f"Site returned status code: {response.status_code}"
                
        except requests.exceptions.ConnectionError:
            error_msg = "Could not connect to this site. It might be down or does not exist."
        except requests.exceptions.Timeout:
            error_msg = "Connection timed out. The site is too slow."
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            
        if error_msg:
            flash(error_msg, 'danger')
            
    return render_template("scrape.html", results=results, page_url=page_url)

@app.route('/content', methods=['GET', 'POST'])
@login_required
def extract_content_route():
    content = ""
    title = ""
    if request.method == 'POST':
        page_url = request.form.get("page_url")
        page_url = validate_url(page_url) # Fix URL here too
        try:
            response = requests.get(page_url, timeout=10)
            doc = Document(response.text)
            title = doc.short_title()
            soup = BeautifulSoup(doc.summary(), 'html.parser')
            content = soup.get_text(separator="\n")
        except Exception as e:
            flash(f"Error extracting content: {str(e)}", 'danger')
    return render_template("content.html", content=content, title=title)

@app.route('/logout')
@login_required
def logout_route():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✅ Database initialized successfully.")
    app.run(debug=True)