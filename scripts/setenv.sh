#!/usr/bin/env bash

# Set the required vars here before running deploy.sh
# you can change the values here or have them available in your env prior to running the script 

# Only export if not already set (optional variables)
export CLUSTER_NAME="${CLUSTER_NAME:="dev"}"          # Default empty if not set
export REGISTRY_URL="${REGISTRY_URL:="https://index.docker.io/v1/"}"  # Default empty if not set
export REGISTRY_USERNAME="${REGISTRY_USERNAME:=}" # Default empty if not set
export REGISTRY_PASSWORD=${REGISTRY_PASSWORD:=} # Default empty if not set
export REGISTRY_EMAIL="${REGISTRY_EMAIL:=}"      # Default empty if not set
export MAX_CVSS_SCORE="${MAX_CVSS_SCORE:="7"}" # Default 7 if not set
 
# Notify user of any defaults applied (except password)
echo "CLUSTER_NAME is set to '${CLUSTER_NAME}'"
echo "REGISTRY_URL is set to '${REGISTRY_URL}'"
echo "REGISTRY_USERNAME is set to '${REGISTRY_USERNAME}'"
echo "REGISTRY_EMAIL is set to '${REGISTRY_EMAIL}'"
echo "REGISTRY_PASSWORD is set"
echo "SBOM_FORMAT is set to '${SBOM_FORMAT}'"
