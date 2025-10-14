# Linkwise - Personal Link Aggregator

A minimalist web app to save and categorize web links with automatic article summarization and tag generation using AI.

**This version uses:**
- ✅ **SQLite** for database (no external DB service needed)
- ✅ **Flask-Login** for authentication (no Firebase/Supabase)
- ✅ **Session-based auth** (simple cookies)
- ✅ **Single file deployment** ready

## Features

- 🔐 Built-in email/password authentication
- 📝 Automatic article content extraction
- 🤖 AI-powered summaries and tags using Gemini API
- 🔍 Real-time search and filtering
- 📱 Responsive design
- 🚀 Deploy anywhere (Railway, Render, Fly.io, etc.)

## Tech Stack

**Frontend:**
- HTML, CSS, JavaScript (Vanilla)

**Backend:**
- Python Flask
- Flask-Login (session-based auth)
- SQLite (embedded database)
- BeautifulSoup4 (article parsing)
- Google Gemini API (AI summaries)

## Quick Start (Local Development)

1. **Clone the repository**

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Get Gemini API Key:**
   - Go to [Google AI Studio](https://aistudio.google.com/api-keys) and create an API key

4. **Set environment variables:**
   ```bash
   export GEMINI_API_KEY='your-gemini-api-key'
   export SECRET_KEY='your-random-secret-key'  # Any random string
   ```

5. **Run the app:**
   ```bash
   python app.py
   ```

6. **Access at:** `http://localhost:8080`

The SQLite database (`linkwise.db`) will be created automatically in the project directory.
