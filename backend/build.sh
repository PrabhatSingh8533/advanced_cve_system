#!/bin/bash
set -e

echo "Python version:"
python --version

echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Build complete!"
