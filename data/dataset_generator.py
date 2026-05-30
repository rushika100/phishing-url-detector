"""
Dataset Generator
Creates a labeled dataset of phishing and legitimate URLs
and extracts features for ML training.
"""

import pandas as pd
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.feature_extractor import extract_features, features_to_vector

# ─────────────────────────────────────────────
# SAMPLE URLS — labeled 0=legit, 1=phishing
# ─────────────────────────────────────────────

LEGIT_URLS = [
    "https://google.com/search?q=python",
    "https://github.com/login",
    "https://stackoverflow.com/questions",
    "https://youtube.com/watch?v=abc123",
    "https://microsoft.com/en-us/windows",
    "https://amazon.com/products",
    "https://linkedin.com/in/profile",
    "https://wikipedia.org/wiki/Python",
    "https://reddit.com/r/programming",
    "https://netflix.com/browse",
    "https://twitter.com/home",
    "https://apple.com/iphone",
    "https://instagram.com/explore",
    "https://sbi.co.in/web/personal-banking",
    "https://hdfcbank.com/content/bbp/repositories",
    "https://irctc.co.in/nget/train-search",
    "https://paytm.com/offer/cashback",
    "https://flipkart.com/search?q=phone",
    "https://digitalindia.gov.in/",
    "https://incometax.gov.in/iec/foportal",
]

PHISHING_URLS = [
    "http://secure-login-paypal-verify.xyz/account/confirm",
    "http://192.168.1.1/admin/login.php",
    "https://accounts.google.com.verify-login.tk/signin",
    "http://g00gle-secure-update.ml/verify?user=you",
    "http://paypa1-alert-confirm.ga/login/secure",
    "https://login.verify.facebook.com.evil.xyz/account",
    "http://amazon-prize-winner-click.top/free?ref=abc",
    "http://secure-sbi-netbanking-verify.tk/login",
    "https://hdfc-bank-alert-update.xyz/confirm-account",
    "http://irctc-free-ticket-winner.ml/claim?id=123",
    "http://income-tax-refund-verify.ga/login",
    "http://paytm-lucky-winner-prize.cf/claim",
    "http://update-your-account.verify-login.xyz/signin",
    "http://credential-verify.suspended-account.tk/",
    "https://unusual.activity.alert.banking.verify.ml/",
    "http://click.free.prize.winner.lucky.top/confirm",
    "http://1nstagram-verify-account.xyz/login",
    "http://rn1crosoft-update-urgent.ga/windows/verify",
    "http://appleid.apple.com.phish.tk/account/login",
    "http://amaz0n-order-confirm-urgent.xyz/login?ref=x",
]

def build_dataset():
    rows = []

    print("Extracting features from legitimate URLs...")
    for url in LEGIT_URLS:
        try:
            feats = extract_features(url)
            vec   = features_to_vector(feats)
            rows.append(vec + [0])  # 0 = legitimate
        except Exception as e:
            print(f"  Skipped {url}: {e}")

    print("Extracting features from phishing URLs...")
    for url in PHISHING_URLS:
        try:
            feats = extract_features(url)
            vec   = features_to_vector(feats)
            rows.append(vec + [1])  # 1 = phishing
        except Exception as e:
            print(f"  Skipped {url}: {e}")

    columns = [
        "url_length", "domain_length", "dot_count", "hyphen_count",
        "is_https", "has_ip", "subdomain_count", "suspicious_tld",
        "phishing_keywords", "has_at_symbol", "has_double_slash",
        "special_char_count", "domain_entropy", "brand_in_domain",
        "path_length", "label"
    ]

    df = pd.DataFrame(rows, columns=columns)
    df.to_csv("data/dataset.csv", index=False)
    print(f"\nDataset saved! {len(df)} URLs total.")
    print(f"Legitimate: {len(df[df.label==0])}  |  Phishing: {len(df[df.label==1])}")
    print(df.head())
    return df

if __name__ == "__main__":
    build_dataset()