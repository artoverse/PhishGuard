# PhishGuard 

PhishGuard is a real-time, highly concurrent web application designed to detect and analyze phishing lookalike domains. It uses a robust hybrid architecture that combines rapid DNS permutation scanning with deep threat enrichment and an evidence-weighted risk scoring engine.

## Key Features

- **DNS Permutation Scanning:** Leverages `dnstwist` to intelligently fuzz target domains, generating and resolving hundreds of potential lookalike domains in concurrent background threads.
- **Deep Threat Enrichment:** Automatically probes active domains for:
  - **WHOIS & Domain Age:** Detecting recently registered domains.
  - **VirusTotal Intelligence:** Cross-referencing domains against dozens of antivirus engines.
  - **Web Content Analysis:** Scanning live page contents for suspicious elements (e.g., password forms, credential stealing external actions).
  - **SSL Certificate Validation:** Examining certificate presence and validity.
- **Evidence-Weighted Risk Scoring:** Employs a highly detailed deterministic scoring engine (evaluated out of 100 points). Evaluates 6 independent signal groups—VirusTotal, Age, Visual Similarity, Structure, Content, and SSL—preventing any single feature from skewing the results and offering precise risk attribution.
- **Real-Time Dashboard:** A responsive, modern frontend built with Flask, WebSockets (`Flask-SocketIO`), and SQLite (operating in WAL mode for high concurrency). Administrators can view live scan logs streaming directly from background threads.
- **Role-Based Access Control:** Built-in user authentication with admin approval workflows ensures that only authorized analysts can queue and manage scans.

## 🛠️ Technology Stack

- **Backend:** Python, Flask, Flask-SocketIO, SQLAlchemy, SQLite
- **Intelligence & Scanning:** `dnstwist`, VirusTotal API, `python-whois`, `Levenshtein`, `BeautifulSoup`

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/phishguard.git
   cd phishguard
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Variables:**
   Copy `.env.example` to `.env` and configure your API keys.
   ```bash
   cp .env.example .env
   ```
   *Note: A VirusTotal API key is essential for accurate intelligence grading.*

5. **Initialize Database and Start Application:**
   ```bash
   python app.py
   ```
   - The application will automatically create the database schema inline.
   - A default administrator account is generated (`username: admin`, `password: admin`).

## 🖥️ Usage

1. **Login:** Access the dashboard at `http://127.0.0.1:5000` with the default admin credentials.
2. **Start a Scan:** Enter a target brand domain (e.g., `example.com`) to begin the scan.
3. **Monitor Live Logs:** Dive into the Session Logs interface to watch the backend worker threads run the DNS resolution and threat enrichment in pure real-time.
4. **Review Results:** Evaluate the detected domains with their evidence-weighted scores (Safe , Suspicious , Malicious ), and review detailed breakdown reports highlighting specific risk components.

##  Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

##  License

This project is licensed under the MIT License.

