"""
Train model on real UCI Phishing Dataset (11,054 URLs)
"""

import pandas as pd
import pickle
import os
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import json

print("Loading real dataset (11,054 URLs)...")
df = pd.read_csv("data/phishing.csv")

# Drop Index column, convert -1/1 labels to 0/1
df = df.drop("Index", axis=1)
df["class"] = df["class"].map({1: 0, -1: 1})  # 0=legit, 1=phishing

X = df.drop("class", axis=1)
y = df["class"]

print(f"Total samples  : {len(df)}")
print(f"Legitimate     : {len(df[df['class']==0])}")
print(f"Phishing       : {len(df[df['class']==1])}")
print(f"Features       : {X.shape[1]}")

# ─────────────────────────────────────────────
# SPLIT
# ─────────────────────────────────────────────

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"\nTraining samples : {len(X_train)}")
print(f"Testing  samples : {len(X_test)}")

# ─────────────────────────────────────────────
# TRAIN TWO MODELS, PICK BEST
# ─────────────────────────────────────────────

print("\nTraining Random Forest...")
rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
rf_score = accuracy_score(y_test, rf.predict(X_test))
print(f"Random Forest Accuracy : {rf_score*100:.2f}%")

print("Training Gradient Boosting...")
gb = GradientBoostingClassifier(n_estimators=150, random_state=42)
gb.fit(X_train, y_train)
gb_score = accuracy_score(y_test, gb.predict(X_test))
print(f"Gradient Boosting Accuracy : {gb_score*100:.2f}%")

# Pick best
if rf_score >= gb_score:
    model = rf
    model_name = "Random Forest"
    best_score = rf_score
else:
    model = gb
    model_name = "Gradient Boosting"
    best_score = gb_score

print(f"\nBest model: {model_name} ({best_score*100:.2f}%)")

# ─────────────────────────────────────────────
# EVALUATE
# ─────────────────────────────────────────────

y_pred = model.predict(X_test)

print("\n── Classification Report ───────────────")
print(classification_report(y_test, y_pred,
      target_names=["Legitimate", "Phishing"]))

cm = confusion_matrix(y_test, y_pred)
print("── Confusion Matrix ────────────────────")
print(f"  True  Legit   : {cm[0][0]}  |  False Phishing : {cm[0][1]}")
print(f"  False Legit   : {cm[1][0]}  |  True  Phishing : {cm[1][1]}")

print("\n── Cross Validation (5-fold) ───────────")
cv_scores = cross_val_score(model, X, y, cv=5)
print(f"  Scores : {[round(s*100,2) for s in cv_scores]}")
print(f"  Mean   : {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)")

print("\n── Top 10 Features ─────────────────────")
importances = sorted(zip(X.columns, model.feature_importances_),
                     key=lambda x: x[1], reverse=True)
for feat, score in importances[:10]:
    bar = "█" * int(score * 80)
    print(f"  {feat:<25} {bar} {score:.3f}")

# ─────────────────────────────────────────────
# SAVE MODEL + METADATA
# ─────────────────────────────────────────────

os.makedirs("models", exist_ok=True)

with open("models/phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

# Save metadata for web UI display
metadata = {
    "model_name"   : model_name,
    "accuracy"     : round(best_score * 100, 2),
    "cv_mean"      : round(cv_scores.mean() * 100, 2),
    "cv_std"       : round(cv_scores.std() * 100, 2),
    "total_samples": len(df),
    "features"     : X.columns.tolist(),
    "confusion_matrix": cm.tolist(),
    "top_features" : [(f, round(s, 4)) for f, s in importances[:10]]
}

with open("models/metadata.json", "w") as f:
    json.dump(metadata, f, indent=2)

print(f"\nModel saved    → models/phishing_model.pkl")
print(f"Metadata saved → models/metadata.json")
print(f"\nFinal Accuracy : {best_score*100:.2f}%")