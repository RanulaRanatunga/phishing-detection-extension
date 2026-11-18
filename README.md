# Phishing Detection Browser Extension

A Chrome extension (Manifest V3) that flags phishing websites in real time. A Random Forest model runs inside the browser, so no URL or browsing data leaves your machine.

## How it works

The extension extracts 24 features from each URL (length, entropy, subdomain count, suspicious tokens, unusual TLDs and more), runs them through the Random Forest, and checks a local blacklist:

1. URL on the blacklist: **phishing**
2. Model probability of 0.90 or higher: **phishing**
3. Model probability of 0.60 or higher: **suspicious**
4. Anything else: **legitimate**

I trained and evaluated Random Forest and XGBoost models on approximately 8,000 URLs. The shipped model reaches an 8% false positive rate; I treated false positives as the main design constraint, because users switch off a warning that fires too often.

## Install

1. Clone this repository.
2. Open `chrome://extensions/` and turn on **Developer mode**.
3. Click **Load unpacked** and select `phishing-extension/phishing-detection-extension/phishing-extension/`.

The popup shows the current URL, the decision and the model's probability.

## Try it safely

`test-sites/` contains five demo pages (three phishing-style, two suspicious-style) and a small server to host them locally. They submit no data. Setup steps are in the [extension README](phishing-extension/phishing-detection-extension/phishing-extension/README.md#hosted-demo-pages).

## Retrain the model

`scripts/retrain.sh` runs the training notebook and regenerates `model/model_rf.js`. The extension README includes a cron example for weekly retraining.

## Repository layout

| Path | Contents |
|---|---|
| `phishing-extension/.../phishing-extension/` | The extension: `main.js`, `url_analyzer.js`, `warning_overlay.js`, popup, model, blacklist |
| `train_model.ipynb` | Feature engineering, training and evaluation |
| `scripts/retrain.sh` | One-command retraining |
| `test-sites/` | Local demo phishing pages |

## Limitations

Use it to learn how URL-based phishing detection works, not as a replacement for a production anti-phishing service.

## Licence

MIT. See [LICENSE](LICENSE).
