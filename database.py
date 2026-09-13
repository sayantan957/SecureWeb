import sqlite3
from datetime import datetime
from flask import g
from config import Config

def get_db():
    """
    Get a thread-local SQLite database connection.
    Stored on Flask's 'g' context object during requests.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(Config.DATABASE_PATH)
        # Enable foreign key constraint enforcement in SQLite
        g.db.execute("PRAGMA foreign_keys = ON;")
        # Enable row-as-dictionary access
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """
    Initialize database tables for Users and Files if they do not exist.
    """
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # 1. Users Table
    # Stores authentication credentials with hashed passwords
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # 2. Files Table
    # Stores metadata of uploaded files. Stored filename is randomized (UUID)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            stored_filename TEXT UNIQUE NOT NULL,
            file_size INTEGER NOT NULL,
            file_type TEXT NOT NULL,
            upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            scan_status TEXT NOT NULL,
            scan_result TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """)

    # Index on user_id for fast file retrieval by owner
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);
    """)

    conn.commit()
    conn.close()

# ----------------------------------------------------------------------
# User Database Helpers
# ----------------------------------------------------------------------

def create_user(username, email, password_hash):
    """Insert a new user record."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (username, email, password_hash)
    )
    db.commit()
    return cursor.lastrowid

def get_user_by_username(username):
    """Retrieve user by username."""
    db = get_db()
    return db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

def get_user_by_email(email):
    """Retrieve user by email."""
    db = get_db()
    return db.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()

def get_user_by_id(user_id):
    """Retrieve user by primary key ID."""
    db = get_db()
    return db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()

# ----------------------------------------------------------------------
# File Database Helpers
# ----------------------------------------------------------------------

def create_file_record(user_id, original_filename, stored_filename, file_size, file_type, scan_status, scan_result=""):
    """Insert a newly uploaded file record."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO files (
            user_id, original_filename, stored_filename, file_size, file_type, scan_status, scan_result
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, original_filename, stored_filename, file_size, file_type, scan_status, scan_result))
    db.commit()
    return cursor.lastrowid

def get_user_files(user_id):
    """Retrieve all files owned by a specific user."""
    db = get_db()
    return db.execute(
        "SELECT * FROM files WHERE user_id = ? ORDER BY upload_time DESC",
        (user_id,)
    ).fetchall()

def get_file_by_id(file_id):
    """Retrieve file record by ID."""
    db = get_db()
    return db.execute(
        "SELECT * FROM files WHERE id = ?", (file_id,)
    ).fetchone()

def delete_file_record(file_id):
    """Delete a file record from the database."""
    db = get_db()
    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
