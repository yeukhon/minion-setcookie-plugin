#!/bin/bash

set -x

# This script expects an active virtualenv

if [ -z "$VIRTUAL_ENV" ]; then
    echo "abort: no virtual environment active"
    exit 1
fi

case $1 in
    develop)
        python setup.py develop
        go build $PWD/scanner/setcookie_scanner.go
        sudo ln -s $PWD/scanner/setcookie_scanner /usr/bin/setcookie_scanner
        ;;
esac
