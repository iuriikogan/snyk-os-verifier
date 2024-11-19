#!/usr/bin/env bash

set -eou pipefail
IFS=$'\t\n'

# Record the start time
start=$(date +%s)
# Detect the OS
OS=$(uname)

# Function to print the usage information and exit the script with a non-zero status
function print_usage {
    echo "Usage: bash deploy-kind.sh"
    echo "$*"
    exit 1
}




echo "*---- Deployed kind in :" $(( $(date +%s) - start )) "seconds ----*"