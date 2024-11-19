#!/usr/bin/env bash

set -eou pipefail   

# Function to check for required tools
check_required_tools() {
    local tools=("docker" "kubectl" "helm" "kind")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo "Error: $tool is not installed."
            exit 1
        fi
    done
    echo "All required tools are installed."
}

# Function to check if Docker is running
check_docker_running() {
    if docker info &> /dev/null; then
        echo "Docker is running."
    else
        echo "Docker is not running. Starting Docker..."
        start_docker
    fi
}

# Function to start Docker
start_docker() {
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        if ! pgrep -x "Docker" > /dev/null; then
            open --background -a Docker
            echo "Docker is starting on macOS. It might take a few moments."
            while ! docker info &> /dev/null; do
                sleep 1
            done
            echo "Docker is now running."
        else
            echo "Docker is already running on macOS."
        fi
    elif [[ "$(uname)" == "Linux" ]]; then
        # Linux
        if ! systemctl is-active --quiet docker; then
            sudo systemctl start docker
            echo "Docker is starting on Linux."
            while ! docker info &> /dev/null; do
                sleep 1
            done
            echo "Docker is now running."
        else
            echo "Docker is already running on Linux."
        fi
    else
        echo "Unsupported OS: $(uname)"
        exit 1
    fi
}

# Check for required tools
check_required_tools

# Check if Docker is running and start it if necessary
check_docker_running
