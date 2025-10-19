# Vercel Deployment Script for WealthWise (PowerShell)

Write-Host "🚀 Deploying WealthWise to Vercel..." -ForegroundColor Cyan
Write-Host ""

# Check if Vercel CLI is installed
$vercelInstalled = Get-Command vercel -ErrorAction SilentlyContinue
if (-not $vercelInstalled) {
    Write-Host "❌ Vercel CLI not found!" -ForegroundColor Red
    Write-Host "Installing Vercel CLI..." -ForegroundColor Yellow
    npm install -g vercel
}

# Login to Vercel
Write-Host "📝 Please login to Vercel..." -ForegroundColor Yellow
vercel login

Write-Host ""
Write-Host "✅ Logged in successfully!" -ForegroundColor Green
Write-Host ""

# Deploy to production
Write-Host "🔨 Deploying to production..." -ForegroundColor Yellow
vercel --prod

Write-Host ""
Write-Host "✨ Deployment complete!" -ForegroundColor Green
Write-Host "🌐 Your app is now live on Vercel!" -ForegroundColor Cyan
Write-Host ""
Write-Host "📊 To view logs: vercel logs" -ForegroundColor Gray
Write-Host "📋 To view deployments: vercel ls" -ForegroundColor Gray
Write-Host ""
