#!/bin/bash

# Google Cloud Platform Deployment Script
# This script automates the deployment of both backend and frontend to Google Cloud

set -e  # Exit on any error

echo "🚀 Starting Google Cloud Platform Deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}❌ Google Cloud CLI is not installed. Please install it first:${NC}"
    echo "   brew install --cask google-cloud-sdk"
    echo "   or visit: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Check if user is logged in
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
    echo -e "${YELLOW}⚠️  You are not logged in to Google Cloud. Please login first:${NC}"
    echo "   gcloud auth login"
    exit 1
fi

# Get current project
PROJECT_ID=$(gcloud config get-value project)
if [ -z "$PROJECT_ID" ]; then
    echo -e "${RED}❌ No Google Cloud project is set. Please set a project first:${NC}"
    echo "   gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

echo -e "${GREEN}✅ Using project: $PROJECT_ID${NC}"

# Enable required APIs
echo -e "${YELLOW}🔧 Enabling required APIs...${NC}"
gcloud services enable appengine.googleapis.com cloudbuild.googleapis.com

# Check if App Engine is initialized
if ! gcloud app describe &>/dev/null; then
    echo -e "${YELLOW}🏗️  Initializing App Engine...${NC}"
    echo "Please select a region when prompted (recommended: us-central1)"
    gcloud app create
fi

# Deploy Backend
echo -e "${YELLOW}🐍 Deploying Flask Backend...${NC}"
cd backend

# Check if requirements.txt exists
if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}❌ requirements.txt not found in backend directory${NC}"
    exit 1
fi

# Check if app.yaml exists
if [ ! -f "app.yaml" ]; then
    echo -e "${RED}❌ app.yaml not found in backend directory${NC}"
    exit 1
fi

# Deploy backend
echo -e "${YELLOW}📦 Deploying backend to App Engine...${NC}"
gcloud app deploy app.yaml --quiet

# Get backend URL
BACKEND_URL="https://$(gcloud app describe --format='value(defaultHostname)')"
echo -e "${GREEN}✅ Backend deployed successfully at: $BACKEND_URL${NC}"

# Go back to root directory
cd ..

# Deploy Frontend
echo -e "${YELLOW}⚛️  Preparing React Frontend...${NC}"
cd frontend

# Check if package.json exists
if [ ! -f "package.json" ]; then
    echo -e "${RED}❌ package.json not found in frontend directory${NC}"
    exit 1
fi

# Update config.js with the actual backend URL
echo -e "${YELLOW}🔧 Updating frontend configuration...${NC}"
sed -i.bak "s|https://your-app-name.appspot.com|$BACKEND_URL|g" src/config.js
echo -e "${GREEN}✅ Updated API endpoint to: $BACKEND_URL${NC}"

# Install dependencies
echo -e "${YELLOW}📦 Installing frontend dependencies...${NC}"
npm install

# Build React app
echo -e "${YELLOW}🏗️  Building React app...${NC}"
npm run build

# Check if build directory exists
if [ ! -d "build" ]; then
    echo -e "${RED}❌ Build directory not found. Build may have failed.${NC}"
    exit 1
fi

# Deploy frontend
echo -e "${YELLOW}🚀 Deploying frontend to App Engine...${NC}"
gcloud app deploy app.yaml --quiet

# Get frontend URL
FRONTEND_URL="https://$(gcloud app describe --format='value(defaultHostname)')"
echo -e "${GREEN}✅ Frontend deployed successfully at: $FRONTEND_URL${NC}"

# Deployment complete
echo -e "${GREEN}"
echo "🎉 Deployment Complete!"
echo "===================="
echo "Backend API: $BACKEND_URL"
echo "Frontend App: $FRONTEND_URL"
echo "Admin Console: https://console.cloud.google.com/appengine"
echo -e "${NC}"

# Restore original config.js backup
if [ -f "src/config.js.bak" ]; then
    mv src/config.js.bak src/config.js
    echo -e "${YELLOW}📝 Restored original config.js${NC}"
fi

echo -e "${GREEN}✅ Your SQL Injection Scanner is now live on Google Cloud Platform!${NC}"
echo -e "${YELLOW}💡 You can now visit: $FRONTEND_URL${NC}"

# Show next steps
echo -e "${YELLOW}"
echo "Next Steps:"
echo "----------"
echo "1. Visit your deployed app: $FRONTEND_URL"
echo "2. Test the API endpoints: $BACKEND_URL/user"
echo "3. Monitor logs: gcloud app logs tail -s default"
echo "4. Configure custom domain (optional): gcloud app domain-mappings create yourdomain.com"
echo -e "${NC}" 