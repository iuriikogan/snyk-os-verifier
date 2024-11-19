#!/usr/bin/env bash
set -eou pipefail
IFS=$'\t'

source setenv.sh

# Function to print the usage information and exit the script with a non-zero status
function print_usage {
    echo "Usage: bash destroy.sh [--kind]"
    echo "$*"
    exit 1
}

if [[ "$*" == "--kind" ]]; then
    kind delete cluster --name="$CLUSTER_NAME"
    exit 1
fi

helm uninstall gatekeeper -n gatekeeper-system
helm uninstall ratify -n gatekeeper-system
kubectl delete ns gatekeeper-system
kubectl delete ns sbom-demo
echo "deleted all demo resources"