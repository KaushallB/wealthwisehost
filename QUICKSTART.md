# Quick Start Guide - Deploy to Vercel

## Prerequisites

1. **Node.js and npm** (for Vercel CLI)
   - Download from: https://nodejs.org/
   
2. **Vercel Account**
   - Sign up at: https://vercel.com/signup

## Step-by-Step Deployment

### Option 1: Using Vercel CLI (Fastest - Recommended)

1. **Install Vercel CLI**
   ```powershell
   npm install -g vercel
   ```

2. **Login to Vercel**
   ```powershell
   vercel login
   ```

3. **Navigate to your project**
   ```powershell
   cd c:\Users\Acer\Downloads\wealthwisehost
   ```

4. **Deploy**
   ```powershell
   # First deployment (creates project)
   vercel
   
   # Then deploy to production
   vercel --prod
   ```

   **OR use the PowerShell script:**
   ```powershell
   .\deploy.ps1
   ```

5. **Done!** 🎉
   - Vercel will give you a URL like: `https://wealthwise-xyz.vercel.app`
   - Your app will be live immediately!

### Option 2: Using GitHub + Vercel Dashboard

1. **Push to GitHub**
   ```powershell
   git init
   git add .
   git commit -m "Deploy to Vercel"
   git branch -M main
   git remote add origin https://github.com/KaushallB/wealthwisehost.git
   git push -u origin main
   ```

2. **Import to Vercel**
   - Go to: https://vercel.com/new
   - Click "Import Git Repository"
   - Select your repository
   - Vercel will auto-detect Flask and use `vercel.json`
   - Click "Deploy"

3. **Done!** 🎉

## Environment Variables (Important!)

Your `vercel.json` already contains the environment variables, but you can also set them in the Vercel dashboard:

1. Go to your project on Vercel
2. Click "Settings" → "Environment Variables"
3. Add these variables:

| Variable | Value |
|----------|-------|
| `VERCEL` | `true` |
| `DATABASE_URL` | `postgres://avnadmin:AVNS_oeoS7o2hf90qxX469cH@wealthwise-kaushalbikram44-25e1.b.aivencloud.com:18768/defaultdb?sslmode=require` |
| `EMAIL_USER` | `wisewealth32@gmail.com` |
| `EMAIL_PASS` | `azxa ydvg oxfe rmer` |
| `GEMINI_API_KEY` | `AIzaSyBaze8MZi4ZxPWWV0w1dFs50_07lyWtcOs` |
| `SECRET_KEY` | `WealthWise` |

## Testing Your Deployment

After deployment:

1. **Visit your Vercel URL**
2. **Test Login/Registration**
3. **Add expenses/income**
4. **Generate reports**
5. **Test chatbot**

## Common Issues & Solutions

### Issue: "Build Failed"
**Solution:** Check build logs on Vercel dashboard for specific errors

### Issue: "Database Connection Error"
**Solution:** 
- Verify DATABASE_URL in environment variables
- Check if Aiven database is running
- Test connection locally first

### Issue: "Module not found"
**Solution:** Make sure `requirements.txt` includes all dependencies

### Issue: "Reports not saving"
**Solution:** This is expected on Vercel (serverless). Files don't persist. Users should download immediately.

## Updating Your App

After making changes:

```powershell
# Using CLI
vercel --prod

# Using GitHub
git add .
git commit -m "Your changes"
git push
# Vercel auto-deploys on push
```

## Monitoring

### View Logs
```powershell
vercel logs
```

### View Deployments
```powershell
vercel ls
```

### Dashboard
Visit: https://vercel.com/dashboard

## Performance Tips

1. **Cold Starts**: First request may be slow, but subsequent requests are fast
2. **Caching**: Vercel automatically caches static files
3. **CDN**: Your app is served from global CDN
4. **Database**: Keep Aiven database in same region for better performance

## Need Help?

- **Vercel Docs**: https://vercel.com/docs
- **Deployment Guide**: See `VERCEL_DEPLOYMENT.md`
- **Check Logs**: `vercel logs`

---

## What Changed from Render?

✅ **Removed:**
- `render.yaml`
- `Procfile.txt`
- Render environment checks

✅ **Added:**
- `vercel.json` (Vercel configuration)
- `.vercelignore` (files to ignore)
- Aiven PostgreSQL integration
- Faster deployment process

✅ **Updated:**
- Database connection in `app.py`
- Email scheduler in `email_scheduler.py`
- Environment variables
- Documentation

---

**Your app is ready to deploy! 🚀**

Run `.\deploy.ps1` or `vercel --prod` to get started!
