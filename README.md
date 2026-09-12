# DBERT Internship Portal

A comprehensive, monolithic Flask-based application designed to manage the end-to-end lifecycle of the DBERT Internship Program. This platform seamlessly connects interns, mentors, and companies while providing staff with robust administrative tools.

## 🌟 Key Features

* **Multi-Role Dashboards**: Dedicated, secure portals for Interns, Mentors, Companies, and Staff/Admins.
* **Application Pipeline**: Complete state-machine tracking for intern applications (Apply -> Review -> Selected -> Enrolled -> Accepted).
* **Learning Management System (LMS)**: Built-in course catalog, task tracking, module unlocks, and project submissions.
* **AI Interview System**: Integrated Gemini BYOK (Bring Your Own Key) for automated technical interview generation and evaluation.
* **Ambassador & Referral Program**: Built-in coin ledger, referral code tracking, and automated payout tracking.
* **Built-in Messaging**: Direct threaded messaging between platform users (e.g., Intern to Mentor).
* **CV Generator**: Dynamic resume builder that exports to PDF using xhtml2pdf.
* **Robust Security**: Shared-memory rate-limiting, strict nonce-based Content Security Policy (CSP), auto-attaching CSRF tokens, and secure password hashing (legacy SHA-256 fallback to PBKDF2).
* **Automated Emails**: Multi-transport email system (SMTP/SES/cPanel) with HTML templates.

## 🛠️ Tech Stack

* **Backend**: Python 3.10+, Flask
* **Database**: SQLite3 (Auto-initializing, zero-config, WAL mode)
* **Frontend**: HTML5, Vanilla JavaScript, CSS
* **Authentication**: Cookie-based sessions with aggressive expiry and CSRF guards.

## 🚀 Quick Start (Local Development)

### 1. Prerequisites
* Python 3.9+ installed
* Git

### 2. Installation
Clone the repository and set up a virtual environment:
\\\ash
git clone https://github.com/DBERT-INDIA/Internshipportal.git
cd Internshipportal
python -m venv venv

# Windows:
.\venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
\\\

### 3. Environment Configuration
Copy the example environment file and configure your local secrets:
\\\ash
cp .env.example .env
\\\
*Ensure \FLASK_DEBUG=true\ is set in your \.env\ for local development to bypass production security constraints.*

### 4. Run the Application
\\\ash
python app.py
\\\
*Note: The SQLite database (\internship.db\) and all required tables/indexes are automatically created on the first run.*

The application will be available at \http://localhost:5000\.

## 🗄️ Project Structure

* \pp.py\: The core monolithic application containing all routes, database migrations (\init_db\), and business logic.
* \	emplates/\: 60+ Jinja2 HTML templates for the frontend views.
* \static/\: Static assets including CSS stylesheets and CSP-compliant JavaScript.
* \.env.example\: Template for required environment variables.

## 🔐 Default Admin Access
On a fresh database initialization, a default admin account is automatically created using the credentials specified in your \.env\ file (\ADMIN_USERNAME\ and \ADMIN_PASSWORD\).

## 🛡️ Security Notes
* **Production Mode**: Running without `FLASK_DEBUG=true` enforces strict security constraints. You must provide strong environment variables (e.g., `FLASK_SECRET_KEY`, `ADMIN_PASSWORD`) or the application will proactively refuse to start to prevent exposure.
* **Database Connections**: The app utilizes a custom `get_db()` context manager enforcing `sqlite3.Row` factory, robust busy timeouts (8000ms), and WAL journaling mode for concurrent read/write stability.

## 🎨 UI & Animation Stack
* **Smooth Scrolling**: Integrated **Lenis** (`static/js/lenis.min.js`) for hardware-accelerated, inertia-based smooth scrolling synced with animation frames.
* **Motion & Timelines**: Powered by **GSAP** & **ScrollTrigger** (`static/js/gsap.min.js`, `static/js/ScrollTrigger.min.js`) for micro-interactions, hero entrance sequences, and viewport-triggered reveals.
* **React-Bits Component Patterns**: Vanilla JS + CSS implementation of modern interactive patterns including cursor-following Spotlight Cards (`.spotlight-card`), ambient Aurora floating mesh backgrounds (`.aurora-bg`), and physics-based magnetic CTA buttons (`.btn-magnetic`).
* **Design System & Aesthetics**: Luminous layered cosmic obsidian surfaces (`#07080E`, `#0E111D`), frosted glassmorphic navigation (`backdrop-filter`), celestial amber and electric indigo accents, and modern typography (Plus Jakarta Sans, Outfit, Inter).
