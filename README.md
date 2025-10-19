# WealthWise - Personal Finance Management System

A comprehensive Flask-based personal finance management application with expense tracking, income management, financial reports, and AI-powered chatbot assistance.

## Features

- 📊 **Expense & Income Tracking**: Track your daily expenses and income
- 📈 **Financial Reports**: Generate detailed financial reports with charts
- 🤖 **AI Chatbot**: Get financial advice powered by Google Gemini AI
- 📧 **Email Notifications**: Automated daily updates and alerts
- 🔐 **Secure Authentication**: User registration, login with OTP verification
- 📱 **Responsive Design**: Works on desktop and mobile devices

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: PostgreSQL (Aiven Cloud)
- **Deployment**: Vercel
- **AI**: Google Gemini AI
- **Email**: Flask-Mail with Gmail SMTP
- **Charts**: Matplotlib, Seaborn
- **Frontend**: HTML, CSS, JavaScript, Bootstrap

## Deployment

This application is deployed on **Vercel** with **Aiven PostgreSQL** database.

For detailed deployment instructions, see [VERCEL_DEPLOYMENT.md](VERCEL_DEPLOYMENT.md)

### Quick Deploy

```bash
# Install Vercel CLI
npm install -g vercel

# Login to Vercel
vercel login

# Deploy
vercel --prod
```

## Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/KaushallB/wealthwisehost.git
   cd wealthwisehost
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env and set VERCEL=false for local development
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Access the application**
   Open your browser and navigate to `http://localhost:5000`

## Environment Variables

Required environment variables (set in Vercel dashboard or `.env` for local):

- `VERCEL`: Set to `true` for production, `false` for local
- `DATABASE_URL`: Aiven PostgreSQL connection string
- `EMAIL_USER`: Gmail address for sending emails
- `EMAIL_PASS`: Gmail app password
- `GEMINI_API_KEY`: Google Gemini AI API key
- `SECRET_KEY`: Flask secret key

## Database

The application uses PostgreSQL hosted on **Aiven Cloud**. The database includes tables for:
- Users
- Expenses
- Income
- Budget limits
- OTP verification

## License

This is a final year project for educational purposes.

## Contributors

- Kaushal Bikram (KaushallB)
