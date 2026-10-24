# Deploying nostrfy on AWS

Options: **EC2** (VM, recommended), **Lightsail** (simpler VM), or **ECS/Fargate** (containers).

## Option 1: EC2 (recommended)

1. **Launch an instance**: Amazon Linux 2023 or Ubuntu 24.04 LTS, `t3.small` (2 GB RAM) is enough to start. Choose a region close to your users.
2. **Security group**: allow inbound TCP `8080` (and `443` for TLS). Limit the SSH rule to your IP.
3. **SSH in** and follow the generic [VPS guide](vps.md):

```sh
ssh -i your-key.pem ec2-user@<public-ip>        # Ubuntu: ubuntu@<public-ip>
curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrfy/main/install.sh | sudo env INSTALL_DIR=/usr/local/bin sh
sudo useradd --system --create-home --home /var/lib/nostrfy nostrfy
sudo install -d -o nostrfy -g nostrfy -m 0750 /etc/nostrfy
sudo curl -fsSL -o /etc/nostrfy/nostrfy.toml \
  https://raw.githubusercontent.com/iqbqioza/nostrfy/main/deploy/nostrfy.toml
sudo chown nostrfy:nostrfy /etc/nostrfy/nostrfy.toml
sudo chmod 600 /etc/nostrfy/nostrfy.toml
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
2. Create an ECS service (1 task) with an **EBS-backed volume at `/data`** (LMDB persistence — without it, data is lost on redeploys). **Do not use EFS for `/data`**: LMDB needs a local block device with POSIX locks and `mmap`; a network filesystem can corrupt the database or split the writer. Fargate does not provide EBS, so use the EC2 launch type with an EBS volume (or run the relay on EC2 directly).
3. Expose port `8080`; front it with an ALB + ACM certificate for TLS.
4. Inject secrets at runtime with the task definition's secret support / `NOSTRFY_RELAY_PRIVATE_KEY` (and the other `NOSTRFY_*` names). Never put them in `deploy/nostrfy.container.toml`: it is baked into the image. A custom non-secret config can be mounted at `/etc/nostrfy/nostrfy.toml`.

## Elastic IP

Attach an **Elastic IP** to the instance if you stop/start it — otherwise the public IP changes and `public_url` breaks.