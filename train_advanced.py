import pandas as pd
import numpy as np
import re
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_predict, train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

# --- CONFIGURATION ---
DATASET_PATH = 'malicious_phish.csv'
FEEDBACK_PATH = 'feedback.csv'
MODEL_DIR = 'model'
OVERSAMPLE_FACTOR = 20  # How many times to repeat feedback data to force learning

if not os.path.exists(MODEL_DIR):
    os.makedirs(MODEL_DIR)

print("🚀 Starting Advanced Training Pipeline...")

# --- 1. LOAD MAIN DATASET ---
if os.path.exists(DATASET_PATH):
    print(f"   Loading dataset: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
else:
    print(f"❌ Error: {DATASET_PATH} not found.")
    exit()

# --- 2. PREPROCESSING ---
print("   Encoding labels...")
label_encoder = LabelEncoder()
df['label'] = label_encoder.fit_transform(df['type'])

# --- 3. FEATURE EXTRACTION (BATCH) ---
print("   Extracting features (This may take a few minutes)...")

def extract_features_batch(urls):
    df_features = pd.DataFrame()
    urls = urls.fillna('')
    
    df_features['url_length'] = urls.str.len()
    df_features['num_dots'] = urls.str.count(r'\.')
    df_features['num_hyphens'] = urls.str.count('-')
    df_features['num_slashes'] = urls.str.count('/')
    df_features['num_at'] = urls.str.count('@')
    df_features['num_question'] = urls.str.count(r'\?')
    df_features['num_equal'] = urls.str.count('=')
    df_features['num_digits'] = urls.apply(lambda x: len(re.findall(r'\d', str(x))))
    df_features['has_ip'] = urls.apply(lambda x: int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', str(x)))))
    df_features['num_subdomains'] = urls.apply(lambda x: len(str(x).split('.')) - 2)
    
    suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify', 'banking']
    df_features['has_suspicious_words'] = urls.apply(lambda x: int(any(w in str(x).lower() for w in suspicious_keywords)))
    df_features['https'] = urls.apply(lambda x: 1 if 'https' in str(x).lower() else 0)
    
    return df_features

X = extract_features_batch(df['url'])
y = df['label']

# --- 4. NOISE FILTERING (Clean Main Data FIRST) ---
print("🧹 Cleaning Main Data (removing suspicious inconsistencies)...")
# Only clean if dataset is large enough
if len(df) > 1000:
    temp_model = RandomForestClassifier(n_estimators=50, n_jobs=-1, random_state=42)
    y_pred_probs = cross_val_predict(temp_model, X, y, cv=3, method='predict_proba', n_jobs=-1)

    clean_indices = []
    removed_count = 0
    threshold = 0.90 

    for i in range(len(y)):
        true_label = y[i]
        predicted_label = np.argmax(y_pred_probs[i])
        confidence = y_pred_probs[i][predicted_label]
        
        if true_label != predicted_label and confidence > threshold:
            removed_count += 1
        else:
            clean_indices.append(i)

    print(f"   🗑️ Removed {removed_count} suspicious rows from main dataset.")
    X_clean = X.iloc[clean_indices]
    y_clean = y.iloc[clean_indices]
else:
    X_clean = X
    y_clean = y

# --- 5. MERGE FEEDBACK (FORCE LEARNING) ---
if os.path.exists(FEEDBACK_PATH):
    print(f"   Found user feedback! Integrating and Oversampling...")
    try:
        feedback_df = pd.read_csv(FEEDBACK_PATH)
        if not feedback_df.empty:
            # 1. Extract features for feedback URLs
            X_feedback = extract_features_batch(feedback_df['url'])
            # 2. Transform labels (handle unknown labels gracefully)
            y_feedback = label_encoder.transform(feedback_df['type'])
            
            # 3. OVERSAMPLE (Repeat the feedback data X times to force the model to learn it)
            X_feedback_repeated = pd.concat([X_feedback] * OVERSAMPLE_FACTOR, ignore_index=True)
            y_feedback_repeated = np.repeat(y_feedback, OVERSAMPLE_FACTOR)
            
            print(f"   ✅ Added {len(feedback_df)} feedback samples (Repeated {OVERSAMPLE_FACTOR}x for weight).")
            
            # 4. Merge with Clean Data
            X_final = pd.concat([X_clean, X_feedback_repeated], ignore_index=True)
            y_final = np.concatenate([y_clean, y_feedback_repeated])
        else:
            X_final, y_final = X_clean, y_clean
    except Exception as e:
        print(f"   ⚠️ Error loading feedback: {e}")
        X_final, y_final = X_clean, y_clean
else:
    X_final, y_final = X_clean, y_clean

# --- 6. FINAL TRAINING ---
print("🏋️‍♂️ Training Final Model...")
# Use balanced class weight to ensure small classes (like feedback) aren't ignored
final_model = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42, class_weight='balanced')
final_model.fit(X_final, y_final)

# --- 7. SAVE ---
print("💾 Saving updated models...")
joblib.dump(final_model, os.path.join(MODEL_DIR, 'malicious_url_model.pkl'))
joblib.dump(label_encoder, os.path.join(MODEL_DIR, 'label_encoder.pkl'))

print("\n✅ DONE! Feedback has been forced into the model.")