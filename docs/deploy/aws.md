# Deploying nostrfy on AWS

Options: **EC2** (VM, recommended), **Lightsail** (simpler VM), or **ECS/Fargate** (containers).

## Option 1: EC2 (recommended)

1. **Launch an instance**: Amazon Linux 2023 or Ubuntu 24.04 LTS, `t3.small` (2 GB RAM) is enough to start. Choose a region close to your users.
2. **Security group**: allow inbound TCP `8080` (and `443` for TLS). Limit the SSH rule to your IP.
3. **SSH in** and follow the generic [VPS guide](vps.md):

```sh
ssh -i your-key.pem ec2-user@<public-ip>        # Ubuntu: ubuntu@<public-ip>
curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrfy/main/install.sh | sh
sudo mkdir -p /etc/nostrfy
sudo curl -fsSL -o /etc/nostrfy/nostrfy.toml \
  https://raw.githubusercontent.com/iqbqioza/nostrfy/main/deploy/nostrfy.toml
sudo nano /etc/nostrfy/nostrfy.toml                 # set name, public_url, private_key
sudo curl -fsSL -o /etc/systemd/system/nostrfy.service \
  https://raw.githubusercontent.com/iqbqioza/nostrfy/main/deploy/nostrfy.service
sudo systemctl daemon-reload
sudo systemctl enable --now nostrfy
```

4. **Verify**:

```sh
curl http://<public-ip>:8080/health
```

5. **Add TLS (`wss://`)** with certbot + nginx (as in the [VPS guide](vps.md)) or an Application/Network Load Balancer with an ACM certificate — then set `relay.public_url` and restart.

## Option 2: Lightsail

Lightsail instances work exactly like the EC2 guide — the **networking tab** has the firewall rules: open TCP `8080`.

## Option 3: ECS / Fargate (container)

The repository `Dockerfile` downloads the pre-built release binary at build time:

1. Push the image to ECR: `docker buildx build --platform linux/amd64,linux/arm64 -t <account>.dkr.ecr.<region>.amazonaws.com/nostrfy .`
2. Create an ECS service (Fargate, 1 task) with a **mounted EFS volume at `/data`** (LMDB persistence — without it, data is lost on redeploys).
3. Expose port `8080`; front it with an ALB + ACM certificate for TLS.
4. The baked `deploy/nostrfy.container.toml` config can be overridden by mounting your own `nostrfy.toml` at `/etc/nostrfy/nostrfy.toml` (e.g. a fork that copies it into the image).

## Elastic IP

Attach an **Elastic IP** to the instance if you stop/start it — otherwise the public IP changes and `public_url` breaks.