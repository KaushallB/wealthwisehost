# WealthWise - Vercel Deployment Guide

## Database Setup

Your application is now configured to use Aiven PostgreSQL database:
- **Database URL**: postgres://avnadmin:AVNS_oeoS7o2hf90qxX469cH@wealthwise-kaushalbikram44-25e1.b.aivencloud.com:18768/defaultdb?sslmode=require
- Tables have already been created in the database

## Deploying to Vercel

### Prerequisites
1. Install Vercel CLI: `npm install -g vercel`
2. Create a Vercel account at https://vercel.com

### Deployment Steps

#### Option 1: Deploy via Vercel CLI (Recommended)

1. **Login to Vercel**
   ```bash
   vercel login
   ```

2. **Navigate to your project directory**
   ```bash
   cd c:\Users\Acer\Downloads\wealthwisehost
   ```

3. **Deploy**
   ```bash
   vercel
   ```
   - Follow the prompts
   - When asked about settings, use the defaults
   - Vercel will automatically detect your Flask app

4. **Deploy to Production**
   ```bash
   vercel --prod
   ```

#### Option 2: Deploy via GitHub (Alternative)

1. **Push your code to GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial commit for Vercel deployment"
   git branch -M main
   git remote add origin https://github.com/KaushallB/wealthwisehost.git
   git push -u origin main
   ```

2. **Import to Vercel**
   - Go to https://vercel.com/new
   - Import your GitHub repository
   - Vercel will auto-detect the configuration from `vercel.json`

3. **Configure Environment Variables** (if not using vercel.json env)
   - Go to your project settings on Vercel
   - Navigate to "Environment Variables"
   - Add the following:
     - `VERCEL` = `true`
     - `DATABASE_URL` = `postgres://avnadmin:AVNS_oeoS7o2hf90qxX469cH@wealthwise-kaushalbikram44-25e1.b.aivencloud.com:18768/defaultdb?sslmode=require`
     - `EMAIL_USER` = `wisewealth32@gmail.com`
     - `EMAIL_PASS` = `azxa ydvg oxfe rmer`
     - `GEMINI_API_KEY` = `AIzaSyBaze8MZi4ZxPWWV0w1dFs50_07lyWtcOs`
     - `SECRET_KEY` = `WealthWise`

4. **Deploy**
   - Click "Deploy"
   - Vercel will build and deploy your app

## Important Notes

### Vercel Limitations for Flask Apps

1. **Serverless Functions**: Vercel runs Flask as serverless functions, which have some limitations:
   - **10-second timeout** on free plan (50 seconds on Pro)
   - **Cold starts** may cause initial delays (but much faster than Render)
   - **No persistent file storage** - files saved to disk are temporary

2. **File Storage Issue**: Your app saves reports to `Offlinereports/` folder. On Vercel, this won't persist between requests. Solutions:
   - Use cloud storage (AWS S3, Cloudinary, etc.)
   - Generate reports on-demand without saving
   - Use Vercel Blob Storage (paid feature)

### Recommended Changes for Vercel

#### 1. Handle File Storage
Since Vercel has ephemeral file system, consider these options:

**Option A**: Generate reports in memory and send directly to user (no disk storage)

**Option B**: Use a cloud storage service like AWS S3 or Cloudinary

**Option C**: For now, reports will work but won't persist - users need to download immediately

#### 2. Testing Your Deployment

After deployment:
1. Visit your Vercel URL
2. Test login/registration
3. Test database connectivity
4. Test email functionality
5. Test report generation

### Performance Improvements

Vercel advantages over Render:
- ✅ **Much faster cold starts** (usually < 1 second)
- ✅ **Global CDN** for static assets
- ✅ **Automatic HTTPS**
- ✅ **Better caching**
- ✅ **No sleep mode** like Render free tier

### Troubleshooting

1. **Database Connection Issues**
   - Verify the DATABASE_URL is correct in environment variables
   - Check Aiven database is running and accessible
   - Ensure SSL mode is set correctly

2. **Import Errors**
   - Vercel will install all packages from requirements.txt
   - Check build logs for any missing dependencies

3. **Timeout Errors**
   - If operations take > 10 seconds, consider upgrading to Vercel Pro
   - Optimize database queries
   - Use caching where possible

## Local Development

1. Copy `.env.example` to `.env`
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and set `VERCEL=false` for local development

3. Run the app:
   ```bash
   python app.py
   ```

## Monitoring

- View logs: `vercel logs`
- View deployments: `vercel ls`
- View project dashboard: https://vercel.com/dashboard

## Support

For issues:
1. Check Vercel deployment logs
2. Check Aiven database status
3. Verify environment variables are set correctly

---

**Note**: Make sure to add `.env` to `.gitignore` to keep your credentials secure!
