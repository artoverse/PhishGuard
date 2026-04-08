"""
PhishGuard — train_ml.py (DEPRECATED)
======================================
The ML model has been replaced by a deterministic evidence-weighted scoring
system in risk_analyzer.py. This file is kept for reference only.

Why was the ML approach dropped?
---------------------------------
1. Training on synthetic data caused 60%+ of real-world domains to receive
   nearly identical scores because the feature distributions didn't match
   real phishing behaviour.

2. Random Forest probability outputs (predict_proba) cluster around 0.3–0.5
   for dnstwist permutations because most registered lookalikes share similar
   surface features (domain length, entropy, TLD) — the model cannot distinguish
   them without real labelled data.

3. Strong signals like "page has a password form that posts to an external domain"
   cannot be captured by pre-computed feature vectors — they require runtime
   page analysis, which the new enricher/scorer handles directly.

4. The new scoring approach is transparent: you can see exactly why a domain
   scored 68 (e.g. "VT:30 + Age:20 + Struct:15 + Content:3") rather than a
   black-box probability from a model trained on made-up numbers.

If you want to re-introduce ML in the future, use real datasets:
  - PhishTank (https://phishtank.org/developer_info.php)
  - OpenPhish  (https://openphish.com)
  - Tranco top-1M list (https://tranco-list.eu) for legitimate counterpart

The phishguard_rf.pkl file is no longer loaded by the application.
"""

print("ℹ️  train_ml.py is deprecated. PhishGuard now uses deterministic evidence-weighted scoring.")
print("   See risk_analyzer.py for the current scoring implementation.")
