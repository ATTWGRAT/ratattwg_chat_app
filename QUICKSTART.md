# Quick Start Guide - Docker Deployment

## 🚀 5-Minute Deployment

### For Testing (Self-Signed Certificate)

```bash
# 1. Navigate to project directory
cd /path/to/odsi_proj

# 2. Generate test certificates
./docker/generate-self-signed-cert.sh

# 3. Create environment file
cp .env.example .env
# Edit .env and set SECRET_KEY (generate with: python3 -c "import secrets; print(secrets.token_hex(32))")

# 4. Build and run
docker-compose up -d

# 5. Check logs
docker-compose logs -f

# 6. Access application
# Browser: https://localhost (accept security warning)
```

---

### For Production (Let's Encrypt Certificate)

```bash
# 1. Prerequisites
# - Domain pointing to server IP
# - Ports 80, 443 open in firewall

# 2. Stop any running services on ports 80/443
sudo systemctl stop apache2 nginx  # if installed

# 3. Install Certbot
sudo apt install -y certbot

# 4. Generate certificate
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# 5. Copy certificates
cd /path/to/odsi_proj
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ./docker/ssl/cert.pem
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ./docker/ssl/key.pem
sudo chmod 644 ./docker/ssl/cert.pem
sudo chmod 600 ./docker/ssl/key.pem

# 6. Configure environment
cp .env.example .env
nano .env
# Set: SECRET_KEY, CORS_ORIGINS=https://yourdomain.com

# 7. Update nginx config
nano docker/app.conf
# Change: server_name yourdomain.com www.yourdomain.com;

# 8. Build and deploy
docker-compose build
docker-compose up -d

# 9. Verify
curl https://yourdomain.com/health

# 10. Setup auto-renewal
echo '0 2 * * * certbot renew --quiet && cd /path/to/odsi_proj && docker-compose restart' | sudo crontab -
```

---

## 📋 Essential Commands

```bash
# Start application
docker-compose up -d

# Stop application
docker-compose down

# Restart application
docker-compose restart

# View logs (live)
docker-compose logs -f

# View last 100 lines
docker-compose logs --tail=100

# Check container status
docker-compose ps

# Enter container shell
docker exec -it secure-chat-app bash

# Check health
curl -k https://localhost/health

# Rebuild after code changes
docker-compose build --no-cache
docker-compose up -d --force-recreate

# View resource usage
docker stats secure-chat-app

# Backup database
./scripts/backup.sh

# Restore database
./scripts/restore.sh backups/db_20260122_120000.db.gz
```

---

## 🔧 Configuration Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Multi-stage build (frontend + backend + nginx) |
| `docker-compose.yml` | Container orchestration |
| `.env` | Environment variables (SECRET_KEY, etc.) |
| `docker/nginx.conf` | Main nginx configuration |
| `docker/app.conf` | Virtual host config (SSL, proxy, WebSocket) |
| `docker/supervisord.conf` | Process manager (gunicorn + nginx) |
| `docker/ssl/cert.pem` | SSL certificate (public) |
| `docker/ssl/key.pem` | SSL private key (secure) |

---

## 🐛 Common Issues

### "Address already in use"
```bash
# Check what's using port 80/443
sudo lsof -i :80
sudo lsof -i :443
# Kill the process or stop the service
```

### "Permission denied" on SSL files
```bash
sudo chmod 644 docker/ssl/cert.pem
sudo chmod 600 docker/ssl/key.pem
```

### Container won't start
```bash
# Check logs
docker-compose logs

# Most common: missing SSL certificates
./docker/generate-self-signed-cert.sh
```

### "502 Bad Gateway"
```bash
# Check if backend is running
docker exec -it secure-chat-app ps aux | grep gunicorn

# Check backend logs
docker exec -it secure-chat-app tail -f /var/log/gunicorn.err.log
```

### Database not initialized
```bash
docker exec -it secure-chat-app bash
cd /app/backend
python -c "from app import create_app, db; app = create_app('production'); app.app_context().push(); db.create_all()"
exit
```

---

## 📁 Project Structure

```
odsi_proj/
├── Dockerfile                          # Build instructions
├── docker-compose.yml                  # Container config
├── .env                                # Environment variables (create from .env.example)
├── DEPLOYMENT.md                       # Full deployment guide
├── QUICKSTART.md                       # This file
│
├── docker/                             # Docker configuration
│   ├── nginx.conf                      # Nginx main config
│   ├── app.conf                        # Virtual host config (SSL, proxy)
│   ├── supervisord.conf                # Process manager
│   ├── generate-self-signed-cert.sh    # Certificate generator
│   └── ssl/                            # SSL certificates
│       ├── cert.pem                    # Certificate (public)
│       └── key.pem                     # Private key
│
├── scripts/                            # Utility scripts
│   ├── backup.sh                       # Database backup
│   └── restore.sh                      # Database restore
│
├── backend/                            # Flask API
│   ├── app/                            # Application code
│   ├── config.py                       # Configuration
│   ├── run.py                          # Entry point
│   └── requirements.txt                # Python dependencies
│
├── frontend/                           # React app
│   ├── src/                            # Source code
│   ├── public/                         # Static assets
│   ├── package.json                    # Node dependencies
│   └── vite.config.js                  # Build config
│
└── data/                               # Persistent data (created at runtime)
    ├── instance/                       # SQLite database
    ├── logs/                           # Application logs
    └── nginx-logs/                     # Nginx logs
```

---

## 🔒 Security Checklist

- [ ] Strong SECRET_KEY set in `.env`
- [ ] Valid SSL certificates installed (not self-signed)
- [ ] CORS_ORIGINS configured with actual domains
- [ ] Firewall configured (UFW): ports 22, 80, 443 only
- [ ] SSL certificate auto-renewal setup
- [ ] Regular database backups scheduled
- [ ] `.env` file has restricted permissions (600)
- [ ] SSL private key has restricted permissions (600)

---

## 📞 Help

For detailed information, see [DEPLOYMENT.md](DEPLOYMENT.md)

**Quick Links:**
- Full deployment guide: `DEPLOYMENT.md`
- Backend README: `backend/README.md`
- Frontend README: `frontend/README.md`
- Certificate generation: `./docker/generate-self-signed-cert.sh`
- Backup script: `./scripts/backup.sh`
- Restore script: `./scripts/restore.sh`

---

## 🎯 Production Deployment Checklist

Before going live:

1. **Domain & DNS**
   - [ ] Domain configured
   - [ ] DNS A record pointing to server IP
   - [ ] Wait for DNS propagation (check: `nslookup yourdomain.com`)

2. **SSL Certificate**
   - [ ] Let's Encrypt certificate obtained
   - [ ] Certificates copied to `docker/ssl/`
   - [ ] Auto-renewal configured

3. **Configuration**
   - [ ] `.env` file created with production values
   - [ ] SECRET_KEY changed from default
   - [ ] CORS_ORIGINS set to actual domain(s)
   - [ ] `docker/app.conf` updated with server_name

4. **Security**
   - [ ] Firewall enabled (UFW)
   - [ ] Only ports 22, 80, 443 open
   - [ ] File permissions correct (600 for .env, keys)

5. **Deployment**
   - [ ] Code pulled from git
   - [ ] Docker image built
   - [ ] Container started
   - [ ] Health check passes
   - [ ] Logs monitored for errors

6. **Backup & Monitoring**
   - [ ] Backup script scheduled (cron)
   - [ ] Log rotation configured
   - [ ] Monitoring/alerting setup (optional)

7. **Testing**
   - [ ] Can access via HTTPS
   - [ ] No SSL certificate warnings
   - [ ] Registration works
   - [ ] Login works
   - [ ] WebSocket connections work
   - [ ] File uploads work

---

**Need help?** Check `DEPLOYMENT.md` for troubleshooting and advanced configuration.
