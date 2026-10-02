# 🚀 Live Cloud Deployment Guide

This repository is pre-configured for instant 1-click cloud deployment on **Render**, **Railway**, **Fly.io**, or any standard Docker host.

---

## Option 1: Deploy to Render (Recommended — Free & 1-Click)

1. Push your repository to **GitHub** or **GitLab**.
2. Go to [https://dashboard.render.com/](https://dashboard.render.com/) and click **"New +"** → **"Web Service"**.
3. Select your repository.
4. Render will automatically detect the settings from [`render.yaml`](file:///c:/Users/gajul/Music/Cyber%20Projects/render.yaml):
   - **Environment:** `Python`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python lab.py dashboard --host 0.0.0.0 --port $PORT`
5. Click **"Deploy Web Service"**.
6. Your live public URL will be ready at: `https://ai-security-detection-lab.onrender.com`.

---

## Option 2: Deploy to Railway

1. Install the Railway CLI or connect via GitHub at [https://railway.app/](https://railway.app/).
2. Click **"New Project"** → **"Deploy from GitHub repo"**.
3. Railway will automatically build the [`Dockerfile`](file:///c:/Users/gajul/Music/Cyber%20Projects/Dockerfile) and expose the live HTTPS domain.

---

## Option 3: Deploy to Fly.io

1. Run:
   ```bash
   fly launch
   fly deploy
   ```
2. Fly will use [`fly.toml`](file:///c:/Users/gajul/Music/Cyber%20Projects/fly.toml) to containerize and deploy globally.

---

## Option 4: Run Locally with Docker

```bash
docker build -t cyber-security-lab .
docker run -p 8080:8080 cyber-security-lab
```
Navigate to `http://localhost:8080/`.
