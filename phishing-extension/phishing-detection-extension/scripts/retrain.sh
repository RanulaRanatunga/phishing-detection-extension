#!/usr/bin/env bash

# Retrains the model by executing the training notebook in-place.
# This script is intended to be run on a schedule (weekly) and will overwrite
# the existing model output in phishing-extension/model/model_rf.js.

set -euo pipefail

# Ensure we run from the repo root
cd "$(dirname "$0")/.."

# The notebook that trains the model
NOTEBOOK="train_model.ipynb"

if ! command -v jupyter >/dev/null 2>&1; then
  echo "ERROR: jupyter is not installed or not in PATH. Install Jupyter to run this script." >&2
  exit 1
fi

# Run the notebook in-place so it updates any outputs.
jupyter nbconvert --to notebook --execute --inplace "$NOTEBOOK"

echo "Retraining complete: $NOTEBOOK executed successfully."
