# Alan Status Example

This example demonstrates how to implement a status endpoint that queries multiple peers and returns their responses, with a timeout mechanism to ensure the endpoint responds even if some peers do not.

## Run in kubernetes

Build the image and push it to a registry:

```sh
# Build the binary and the docker image
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o status main.go
docker build -t alan-status:latest .
# Load the image into kind
kind load docker-image alan-status:latest
# Deploy to kubernetes
kubectl apply -f k8s.yaml
# Redeploy to update the image
kubectl rollout restart deployment/alan-status
```
