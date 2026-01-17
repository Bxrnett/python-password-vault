"""
Database module for password vault
Handles all database operations for users and passwords
"""
import sqlite3
import hashlib
from typing import Optional, List, Tuple


class Database:
    def __init__(self, db_name: str = "password_vault.db"):
        """Initialize database connection and create tables if they don't exist"""
        self.db_name = db_name
        self.create_tables()
    
    def get_connection(self):
        """Get a database connection"""
        return sqlite3.connect(self.db_name)
    
    def create_tables(self):
        """Create the necessary tables for the password vault"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create passwords table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                site_name TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, site_name)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password: str, salt: str) -> str:
        """Hash a password with a salt"""
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    def create_user(self, username: str, password: str) -> bool:
        """Create a new user account"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Generate a random salt
            import secrets
            salt = secrets.token_hex(16)
            
            # Hash the password
            password_hash = self.hash_password(password, salt)
            
            cursor.execute("""
                INSERT INTO users (username, password_hash, salt)
                VALUES (?, ?, ?)
            """, (username, password_hash, salt))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def verify_user(self, username: str, password: str) -> Optional[int]:
        """Verify user credentials and return user_id if valid"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, password_hash, salt FROM users WHERE username = ?
        """, (username,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            user_id, stored_hash, salt = result
            password_hash = self.hash_password(password, salt)
            
            if password_hash == stored_hash:
                return user_id
        
        return None
    
    def add_password(self, user_id: int, site_name: str, encrypted_password: str) -> bool:
        """Add a new password entry for a user"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO passwords (user_id, site_name, encrypted_password)
                VALUES (?, ?, ?)
            """, (user_id, site_name, encrypted_password))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def update_password(self, user_id: int, site_name: str, encrypted_password: str) -> bool:
        """Update an existing password entry"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE passwords 
            SET encrypted_password = ?, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND site_name = ?
        """, (encrypted_password, user_id, site_name))
        
        affected_rows = cursor.rowcount
        conn.commit()
        conn.close()
        
        return affected_rows > 0
    
    def get_password(self, user_id: int, site_name: str) -> Optional[str]:
        """Get the encrypted password for a specific site"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT encrypted_password FROM passwords
            WHERE user_id = ? AND site_name = ?
        """, (user_id, site_name))
        
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else None
    
    def get_all_sites(self, user_id: int) -> List[str]:
        """Get all site names for a user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT site_name FROM passwords
            WHERE user_id = ?
            ORDER BY site_name
        """, (user_id,))
        
        results = cursor.fetchall()
        conn.close()
        
        return [row[0] for row in results]
    
    def delete_password(self, user_id: int, site_name: str) -> bool:
        """Delete a password entry"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM passwords
            WHERE user_id = ? AND site_name = ?
        """, (user_id, site_name))
        
        affected_rows = cursor.rowcount
        conn.commit()
        conn.close()
        
        return affected_rows > 0
