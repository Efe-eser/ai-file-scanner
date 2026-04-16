# ai-file-scanner (FileXray)

## Deployment (EC2 / Docker)

### Goal
- Keep the backend reachable **only** via the local reverse proxy (Nginx/ALB on the same host), not directly from the internet.
- Ensure the container always restarts with the correct port mapping so you don't get `502 Bad Gateway` again.

### Recommended: Docker Compose
1) Install the compose plugin (Amazon Linux / many EC2 images):

```bash
sudo yum install -y docker-compose-plugin
docker compose version
```

2) Start (or restart) the app using the provided `compose.yml`:

```bash
docker compose up -d
docker ps
```

You should see the port mapping like:
- `127.0.0.1:8000->8000/tcp`

That means the app is **not** exposed publicly; only local services (like Nginx on the same instance) can reach it.

### If you use Nginx on the same host
Point your upstream to:
- `http://127.0.0.1:8000`

### Common check when you see 502
If your domain returns `502 Bad Gateway`, verify the container is up and the port is mapped:

```bash
docker ps
docker port filexray
curl -I http://127.0.0.1:8000/
```

