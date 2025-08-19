#!/usr/bin/env python3
"""
Database Migration Script for Cybersecurity Reporting Agent
Adds logo_url column to organizations table
"""

import sqlite3
import os

def migrate_database():
    """Migrate the database to add logo_url column."""
    db_path = "cybersecurity_users.db"
    
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found. Creating new database...")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if logo_url column already exists
        cursor.execute("PRAGMA table_info(organizations)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'logo_url' not in columns:
            print("Adding logo_url column to organizations table...")
            cursor.execute("ALTER TABLE organizations ADD COLUMN logo_url TEXT")
            conn.commit()
            print("✅ Successfully added logo_url column")
        else:
            print("✅ logo_url column already exists")
        
        # Verify the column was added
        cursor.execute("PRAGMA table_info(organizations)")
        columns = [column[1] for column in cursor.fetchall()]
        print(f"Current columns: {columns}")
        
        conn.close()
        print("Database migration completed successfully!")
        
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    print("🔄 Starting database migration...")
    migrate_database()
    print("🏁 Migration script completed!")
