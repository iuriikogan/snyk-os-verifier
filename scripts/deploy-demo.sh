#! /usr/bin/env bash
set -ou pipefail

# Function to print the usage information and exit the script with a non-zero status
function print_usage {
    echo "Usage: bash deploy-demo.sh"
    echo "$*"
    exit 1
}

## Deploy gatekeeper
echo "*---- deploying gatekeeper ----*"
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts

helm install gatekeeper/gatekeeper \
  --name-template=gatekeeper \
  --namespace gatekeeper-system --create-namespace \
  --set enableExternalData=true \
  --set validatingWebhookTimeoutSeconds=5 \
  --set mutatingWebhookTimeoutSeconds=2 \
  --set externaldataProviderResponseCacheTTL=10s

kubectl create secret docker-registry ratify-regcred -n gatekeeper-system \
  --docker-server="${REGISTRY_URL}" \
  --docker-username="${REGISTRY_USERNAME}" \
  --docker-password="${REGISTRY_PASSWORD}" \
  --docker-email="${REGISTRY_EMAIL}"

echo "*---- deploying ratify ----*"
# Deploy Ratify
helm repo add ratify https://ratify-project.github.io/ratify

# download the notary CaA certificate
curl -sSLO https://raw.githubusercontent.com/deislabs/ratify/main/test/testdata/notation.crt
# install ratify
helm install ratify  \
  ratify/ratify --atomic \
  --namespace gatekeeper-system \
  --set-file notationCerts={./notation.crt} \
  --set featureFlags.RATIFY_CERT_ROTATION=true \
  --set policy.useRego=true \
  --set oras.authProviders.k8secretsEnabled=true \
  --set plugins.

kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=ratify -n gatekeeper-system --timeout=90s

kubectl create ns snyk-os-demo

echo "*---- created demo namespace ----*"

kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=gatekeeper -n gatekeeper-system --timeout=90s

echo "*---- Deploying Verifier Resouce to register the Plugin ----*"
kubectl create -f 
# kubectl create -f manifests/resources/gatekeeper/gatekeeper-vulns-constraint-template.yaml
# kubectl create -f manifests/resources/gatekeeper/gatekeeper-sbom-constraint.yaml
# kubectl create -f ./manifests/resources/ratify/
