#!/bin/bash
# Set up a 'venv' and run sphinx to build the docs!

python3 -m venv build/docs/venv
source build/docs/venv/bin/activate
python -m pip install --upgrade pip -r  docs/requirements.txt
sphinx-build -M html docs build/docs 2>&1 \
	| sed '/WARNING: more than one target found for .any. cross-reference.*:doc:.*:js:class:/d'
