# Phishing Detection Chrome Extension

Local-first phishing URL detection extension for Chrome (Manifest V3).  
The extension extracts URL features, runs a Random Forest model in-browser, and combines that with blacklist matching.

## What This Project Contains

- `popup.html`: extension popup UI
- `main.js`: all extension logic in one file (UI + feature extraction + ML + decision)
- `model/model_rf.js`: converted Random Forest model
- `data/blacklist.json`: known phishing URL list
- `icons/`: extension icons

## Quick Setup

Load the extension:

1. Open `chrome://extensions/`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select this folder

## Retraining the Model

A weekly retrain can be performed by running the included script:

```bash
./scripts/retrain.sh
```

That script executes `train_model.ipynb` and will overwrite `model/model_rf.js`.

To run it on a schedule, add a cron entry (example runs every Sunday at 03:00):

```cron
0 3 * * 0 /path/to/phishing-detection-extension/scripts/retrain.sh >> /tmp/phishing-retrain.log 2>&1
```

Replace `/path/to/phishing-detection-extension` with the repo path on your machine.

## Runtime Decision Logic

Current logic:

1. If URL is in blacklist -> `phishing`
2. Else if model probability >= `0.90` -> `phishing`
3. Else if model probability >= `0.60` -> `suspicious`
4. Else -> `legitimate`

## Feature Set (24 Features)

The model uses 24 URL-based features (in this exact order):

1. `len_url`
2. `len_host`
3. `len_path`
4. `num_dots`
5. `num_hyphens`
6. `num_digits`
7. `num_params`
8. `has_at`
9. `has_ip`
10. `scheme_https`
11. `suspicious_token_hits`
12. `max_token_len`
13. `tld_len`
14. `is_long_tld`
15. `num_subdomains`
16. `entropy_url`
17. `entropy_domain`
18. `uses_shortening`
19. `unusual_tld`
20. `special_chars_domain`
21. `special_chars_path`
22. `special_chars_query`
23. `has_suspicious_file`
24. `in_top1m`

## Validation Checklist

- Extension loads with no errors in `chrome://extensions/`
- Popup displays current URL + decision + probability
- `model/model_rf.js` exists and loads correctly
- `data/blacklist.json` contains URLs
- Feature extraction output length is 24

## Hosted Demo Pages

Use the hostname demo server in `test-sites/serve_hosted_demos.py` for safe browser testing.

1. Add these hostnames to `/etc/hosts`:

```text
127.0.0.1 verify-paypal-login.test bank-security-alert.test microsoft-auth-check.test local-docs localhost-review
```

2. Start the demo server from `test-sites/`:

```bash
sudo python3 serve_hosted_demos.py --port 80
```

3. Open the hub page:

```text
http://127.0.0.1/
```

That hub links to:

- 3 phishing-style hosted pages
- 2 suspicious-style hosted pages

These pages are for extension testing only and do not submit data.

## Recommended Submission Files

- Extension source folder (`phishing-extension/`)
- Converted model file (`model/model_rf.js`)
- Evaluation results (accuracy/precision/recall/F1/ROC-AUC)
- Screenshots of the popup on safe/suspicious test URLs

Detailed pre-submission list: `SUBMISSION_CHECKLIST.md`.

## Notes

- All processing runs locally, no data is sent to any server.
- This extension is a university project and should not replace a proper anti-phishing solution.
