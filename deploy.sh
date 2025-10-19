#!/bin/bash
# Vercel Deployment Script for WealthWise

echo "🚀 Deploying WealthWise to Vercel..."
echo ""

# Check if Vercel CLI is installed
if ! command -v vercel &> /dev/null
then
    echo "❌ Vercel CLI not found!"
    echo "Installing Vercel CLI..."
    npm install -g vercel
fi

# Login to Vercel
echo "📝 Please login to Vercel..."
vercel login

echo ""
echo "✅ Logged in successfully!"
echo ""

# Deploy to production
echo "🔨 Deploying to production..."
vercel --prod

echo ""
echo "✨ Deployment complete!"
echo "🌐 Your app is now live on Vercel!"
echo ""
echo "📊 To view logs: vercel logs"
echo "📋 To view deployments: vercel ls"
echo ""
