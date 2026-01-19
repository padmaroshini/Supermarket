# Supermarket SaaS

## Overview
A comprehensive supermarket management system built with Flask and PostgreSQL. This application provides inventory management, billing, user management, store management, and reporting features for supermarket operations.

## Project Structure
- `app.py` - Main Flask application with all routes and database logic
- `templates/` - HTML templates for all pages
- `static/` - Static assets (JavaScript libraries, CSS)
- `uploads/` - Temporary storage for bulk import Excel files

## Tech Stack
- **Backend**: Python 3.11 with Flask
- **Database**: PostgreSQL (via psycopg2)
- **Frontend**: HTML templates with Bootstrap (inline styling)

## Key Features
- User authentication with role-based access (admin, store users)
- Product inventory management with barcode/QR support
- Bulk product import via Excel files
- Purchase entry and stock management
- Billing with GST calculation
- Sales reports (daily, weekly, monthly)
- Product analytics (top/low selling)
- Store management
- Activity logging

## Default Credentials
- Username: `admin`
- Password: `admin123`

## Running the Application
The application runs on port 5000 with:
```bash
python app.py
```

## Database
Uses Replit's built-in PostgreSQL database. The database is automatically initialized with:
- Required tables (users, products, stores, bills, etc.)
- Default admin user
- Sample products for demo

## Deployment
Configured for autoscale deployment using gunicorn.
