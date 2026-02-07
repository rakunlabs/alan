# Alan Status Example

This example demonstrates how to implement a status endpoint that queries multiple peers and returns their responses, with a timeout mechanism to ensure the endpoint responds even if some peers do not.

## Run in kubernetes

Build the image and push it to a registry:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o status main.go
docker build -t alan-status:latest .
```
