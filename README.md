# Mobile Forensics

## Overview

This project provides malware and forensic scanning for uploaded files using multiple engines:

* **ALEAPP**: Android forensic artifact extraction.
* **YARA**: Malware signature scanning.
* **Regex scanning**: Extracts emails, IPs, domains, and suspicious strings.
* **SQLite DB scanning** for `.db` files.

Files are uploaded, scanned, and results are stored via Prisma ORM.

## Features

* File upload and multi-engine scanning
* Secure handling of archives and large files
* Automated ALEAPP scans of forensic artifacts
* YARA signature-based malware detection
* Regex-based data extraction from files
* SQLite advanced scanning
* Risk scoring based on ML, YARA, and regex results
* Nodemon configured to ignore temporary and upload directories

## Prerequisites

* Node.js (v16+ recommended)
* Python 3 with ALEAPP installed and configured
* YARA installed and available in your system PATH
* `prisma` and database configured (PostgreSQL recommended)
* `npm` or `yarn`

## Installation

```bash
git clone https://github.com/yourusername/mobile-forensics.git
cd mobile-forensics-backend/backend
npm install
```

## Environment Configuration

Create a `.env` file in the `backend` folder with your Neon Postgres connection string:

```env
DATABASE_URL="postgresql://username:password@localhost:5432/your_database_name?schema=public"
"

Adjust other env variables as needed.

## Database Setup and Migration

### 1. Create Database

* Use Neon dashboard or CLI to create your Postgres database.
* Ensure your connection string in `.env` matches the database.

### 2. Run Prisma Migrations

From the backend directory:

```bash
npx prisma migrate dev --name init
```

This applies your Prisma schema and creates necessary tables.

### 3. Generate Prisma Client (if not auto-generated)

```bash
npx prisma generate
```

---

## Running the Backend Server

Start backend with nodemon (ignoring temp folders to prevent restarts):

```bash
npm start
```

* Runs on port 4000 by default
* Temporary files and ALEAPP reports are stored under `backend/reports/`
* Uploaded files saved under `backend/uploads/`

---

## Running FastAPI Backend (related microservices)

### On Linux/macOS

```bash
cd backend/fastapi
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn whatsapp_api:app --reload --host 0.0.0.0 --port 8000
```

### On Windows (PowerShell)

```powershell
cd backend/fastapi
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn whatsapp_api:app --reload --host 0.0.0.0 --port 8000
```

*If execution policy blocks, run once:*

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Running Frontend (Next.js)

```bash
cd frontend
npm run dev
```

* Runs on `http://localhost:3000`
* Backend API should be running on `http://localhost:4000`
* Update frontend API calls to point to backend on port 4000

---

## API Endpoints

* **POST /scan** - Upload file for scanning (YARA, regex, ALEAPP, SQLite)
* Returns detailed scan results with risk scores

---

## Development Notes

* Nodemon configured in `package.json` to ignore these folders:

```json
"start": "nodemon --ignore reports/ --ignore uploads/ --ignore ALEAPP/ ./src/index.js"
```

* ALEAPP output and temporary scan files are in `backend/reports/`
* Uploaded files are in `backend/uploads/`

---

## Troubleshooting

* Nodemon restarting frequently? Verify ignored paths or use `nodemon.json`
* ALEAPP errors? Check Python version, virtual env, and input directory
* YARA errors? Ensure YARA CLI installed and rules file path correct
* Permissions? Ensure backend has read/write to `uploads/` and `reports/`
* Database issues? Confirm connection URL and migrations completed

---

## License

MIT License © ROSHAN MUTTATH FRANCIS
