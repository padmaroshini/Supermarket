# Supermarket SaaS - MySQL Migration

This application has been migrated from SQLite to MySQL.

## Setup Instructions

### 1. Install MySQL Server
- Download and install MySQL Server from https://dev.mysql.com/downloads/mysql/
- Or use XAMPP/WAMP which includes MySQL

### 2. Create Database
Create a database named `supermarket_saas`:

```sql
CREATE DATABASE supermarket_saas;
```

### 3. Update Database Credentials
In `app.py`, update the `get_db_connection()` function with your MySQL credentials:

```python
def get_db_connection():
    conn = mysql.connector.connect(
        host="localhost",        # Your MySQL host
        user="root",            # Your MySQL username
        password="your_password",  # Your MySQL password
        database="supermarket_saas"
    )
    return conn
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Run the Application
```bash
python app.py
```

The database tables will be created automatically when you first run the app.

## Default Admin Login
- Username: admin
- Password: admin123

## Key Changes from SQLite to MySQL
- Replaced `sqlite3` with `mysql.connector`
- Updated SQL syntax (AUTOINCREMENT → AUTO_INCREMENT, etc.)
- Changed query placeholders from `?` to `%s`
- Updated date functions to MySQL equivalents
- Added dictionary cursors for template compatibility