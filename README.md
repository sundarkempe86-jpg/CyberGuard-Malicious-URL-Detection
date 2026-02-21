🛡️ CyberGuard 2.0 – AI-Powered Malicious URL Detection

CyberGuard 2.0 is a powerful machine-learning web application designed to detect malicious URLs in real-time. It classifies URLs into Malware, Phishing, Defacement, and Benign categories using advanced feature extraction and ML models. 

The system goes beyond blacklist-based methods and detects Zero-Day malicious links using lexical analysis and heuristics.

[🚀 Access the Live Demo Here](https://huggingface.co/spaces/sundarkempe-dev/CyberGuard-Detection)

🚀 Features
* 🔍 **Intelligent URL Scanning**: Real-time classification using a trained Random Forest Classifier with 96% precision for malware URLs.
* 🧠 **Continuous Learning**: User feedback stored and used for re-training (Active Learning Loop).
* 🔗 **URL Expansion**: Automatically expands shortened URLs (bit.ly, tinyurl, etc.).
* 👤 **User Dashboard**: Login/Register system, scanning history, and safety scores.
* 🔧 **Heuristic Layer**: Detects Raw IP URLs, suspicious keywords, and excessive special characters.
* 📝 **Whitelist Filtering**: Pre-approved safe domains (Google, Amazon, Microsoft, etc.).

🛠️ Tech Stack
* **Backend**: Python, Flask, SQLAlchemy (SQLite)
* **Machine Learning**: Scikit-Learn, Pandas, Joblib
* **Frontend**: HTML5, Tailwind CSS, Jinja2 Templates
* **Security**: Flask-Login, Flask-Bcrypt

🔧 Installation & Setup

1️⃣ Clone the Repository
terminal:
git clone [https://github.com/sundarkempe86-jpg/CyberGuard-Malicious-URL-Detection.git](https://github.com/sundarkempe86-jpg/CyberGuard-Malicious-URL-Detection.git)
cd CyberGuard-Malicious-URL-Detection

2️⃣ Install Dependencies

terminal: 
pip install -r requirements.txt ,

3️⃣ Add Dataset
The dataset is too large for GitHub. Please download malicious_phish.csv from [Kaggle](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) and place it directly in the root directory.

4️⃣ Train the ML Model
Before running the app, you must generate the model file (approx. 400MB) locally, 

terminal:
python train_advanced.py ,
This will create malicious_url_model.pkl inside the model/ directory.

5️⃣ Run the Application

terminal:
python app.py
Open the app: 👉 http://127.0.0.1:5000/

📁 Project Structure:


CyberGuard_Project/
│── app.py                # Main Flask Application
│── train_advanced.py      # ML Training Script
│── requirements.txt       # Python Dependencies
│── .gitignore             # Excludes large data/model files
│
├── templates/             # UI Components
├── instance/              # Local SQLite Database
└── model/                 # Local Trained Model Files (Generated after training)

📝 License
This project is licensed under the MIT License.
