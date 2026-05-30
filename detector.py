"""
Phishing URL Detector - CLI Tool
Usage: python detector.py
"""

import pickle
import sys
import os
from colorama import Fore, Back, Style, init
from src.feature_extractor import extract_features, features_to_vector, explain_features

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════╗
║         Phishing URL Detector  v1.0              ║
║     ML-powered — for educational use only        ║
╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

def load_model():
    path = "models/phishing_model.pkl"
    if not os.path.exists(path):
        print(f"{Fore.RED}Model not found. Run: python models/train_model.py first{Style.RESET_ALL}")
        sys.exit(1)
    with open(path, "rb") as f:
        return pickle.load(f)

def predict(url, model):
    feats  = extract_features(url)
    vector = features_to_vector(feats)
    pred   = model.predict([vector])[0]
    proba  = model.predict_proba([vector])[0]
    return pred, proba, feats

def display_result(url, pred, proba, feats):
    confidence = proba[pred] * 100
    flags = explain_features(feats)

    print(f"\n  {Fore.WHITE}URL:{Style.RESET_ALL} {url}")
    print(f"  {'─'*48}")

    if pred == 1:
        print(f"  {Back.RED}{Fore.WHITE}  ⚠  PHISHING DETECTED  {Style.RESET_ALL}")
        print(f"  {Fore.RED}Confidence: {confidence:.1f}%{Style.RESET_ALL}")
    else:
        print(f"  {Back.GREEN}{Fore.BLACK}  ✓  LEGITIMATE  {Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Confidence: {confidence:.1f}%{Style.RESET_ALL}")

    # Confidence bar
    bar_len  = 30
    filled   = int(bar_len * proba[pred])
    color    = Fore.RED if pred == 1 else Fore.GREEN
    bar      = color + "█" * filled + Fore.WHITE + "░" * (bar_len - filled)
    print(f"  [{bar}{Style.RESET_ALL}] {confidence:.1f}%")

    # Feature flags
    if flags:
        print(f"\n  {Fore.YELLOW}Warning Signals:{Style.RESET_ALL}")
        for severity, msg in flags:
            icon  = "🔴" if severity == "HIGH" else "🟡"
            color = Fore.RED if severity == "HIGH" else Fore.YELLOW
            print(f"    {icon} {color}{msg}{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.GREEN}No suspicious signals found.{Style.RESET_ALL}")

    # Key features
    print(f"\n  {Fore.CYAN}Key Features:{Style.RESET_ALL}")
    print(f"    Protocol   : {'HTTPS ✓' if feats['is_https'] else 'HTTP ✗'}")
    print(f"    URL Length : {feats['url_length']} chars")
    print(f"    Keywords   : {feats['phishing_keywords']} phishing keywords")
    print(f"    Entropy    : {feats['domain_entropy']}")
    print(f"    Subdomains : {feats['subdomain_count']}")
    print()

def main():
    print(BANNER)
    model = load_model()
    print(f"  {Fore.GREEN}Model loaded successfully!{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Type a URL to scan. Type 'quit' to exit.{Style.RESET_ALL}\n")

    while True:
        try:
            url = input(f"{Fore.CYAN}  Enter URL →{Style.RESET_ALL} ").strip()
            if not url:
                continue
            if url.lower() in ("quit", "exit", "q"):
                print(f"\n  {Fore.CYAN}Goodbye!{Style.RESET_ALL}\n")
                break

            pred, proba, feats = predict(url, model)
            display_result(url, pred, proba, feats)

        except KeyboardInterrupt:
            print(f"\n\n  {Fore.CYAN}Goodbye!{Style.RESET_ALL}\n")
            break
        except Exception as e:
            print(f"  {Fore.RED}Error: {e}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()