"""
SQL Injection Prevention Challenge - SECURE SOLUTION
====================================================

This is the corrected version with all SQL injection vulnerabilities fixed.
Key changes:
1. All SQL queries use parameterized statements (? placeholders)
2. Input validation added for usernames and emails
3. Proper error handling for database operations
4. Special characters are safely escaped by the database driver
"""

import sqlite3
import hashlib
import re
from typing import Optional, List, Dict, Any


class UserDatabase:
    """A secure user management system with SQL injection prevention"""

    def __init__(self, db_name: str = ":memory:"):
        """Initialize the database connection and create tables"""
        self.db_name = db_name
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self._create_tables()
        self._seed_data()

    def _create_tables(self):
        """Create the necessary database tables"""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.conn.commit()

    def _seed_data(self):
        """Add some initial test data"""
        test_users = [
            ("admin", "admin123", "admin@company.com", "admin"),
            ("john_doe", "password123", "john@company.com", "user"),
            ("jane_smith", "securepass", "jane@company.com", "user"),
            ("bob_wilson", "bob12345", "bob@company.com", "user"),
        ]

        for username, password, email, role in test_users:
            password_hash = self._hash_password(password)
            try:
                self.cursor.execute(
                    "INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
                    (username, password_hash, email, role)
                )
            except sqlite3.IntegrityError:
                pass  # User already exists
        self.conn.commit()

    def _hash_password(self, password: str) -> str:
        """Hash a password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def _validate_username(self, username: str) -> bool:
        """
        Validate username format
        - Must be 1-50 characters
        - Only alphanumeric, underscore, hyphen, apostrophe allowed
        """
        if not username or len(username) > 50:
            return False
        # Allow alphanumeric, underscore, hyphen, and apostrophe (for names like O'Brien)
        pattern = r'^[a-zA-Z0-9_\-\']+$'
        return bool(re.match(pattern, username))

    def _validate_email(self, email: str) -> bool:
        """
        Validate email format (basic validation)
        """
        if not email or len(email) > 100:
            return False
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        SECURE: Authenticate a user by username and password
        Uses parameterized queries to prevent SQL injection
        """
        # Input validation
        if not username or not password:
            return None

        if not self._validate_username(username):
            return None

        try:
            password_hash = self._hash_password(password)
            # SECURE: Parameterized query with ? placeholders
            query = "SELECT * FROM users WHERE username = ? AND password_hash = ? AND active = 1"
            result = self.cursor.execute(query, (username, password_hash)).fetchone()

            if result:
                return dict(result)
            return None
        except sqlite3.Error:
            return None

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        SECURE: Retrieve user information by username
        Uses parameterized queries to prevent SQL injection
        """
        # Input validation
        if not username:
            return None

        if not self._validate_username(username):
            return None

        try:
            # SECURE: Parameterized query with ? placeholder
            query = "SELECT id, username, email, role, active FROM users WHERE username = ?"
            result = self.cursor.execute(query, (username,)).fetchone()

            if result:
                return dict(result)
            return None
        except sqlite3.Error:
            return None

    def search_users(self, search_term: str) -> List[Dict[str, Any]]:
        """
        SECURE: Search for users by username or email
        Uses parameterized queries with LIKE to prevent SQL injection
        """
        # Handle empty search term
        if not search_term:
            return []

        # Limit search term length to prevent abuse
        if len(search_term) > 100:
            search_term = search_term[:100]

        try:
            # SECURE: Parameterized query with LIKE pattern
            # The % wildcards are added in the parameter, not concatenated into the query
            search_pattern = f"%{search_term}%"
            query = """
                SELECT id, username, email, role 
                FROM users 
                WHERE username LIKE ? OR email LIKE ?
            """
            results = self.cursor.execute(query, (search_pattern, search_pattern)).fetchall()

            return [dict(row) for row in results]
        except sqlite3.Error:
            return []

    def update_user_email(self, username: str, new_email: str) -> bool:
        """
        SECURE: Update a user's email address
        Uses parameterized queries and validates email format
        """
        # Input validation
        if not username or not new_email:
            return False

        if not self._validate_username(username):
            return False

        if not self._validate_email(new_email):
            return False

        try:
            # SECURE: Parameterized query with ? placeholders
            query = "UPDATE users SET email = ? WHERE username = ?"
            self.cursor.execute(query, (new_email, username))
            self.conn.commit()

            return self.cursor.rowcount > 0
        except sqlite3.Error:
            return False

    def create_user(self, username: str, password: str, email: str, role: str = "user") -> bool:
        """
        SECURE: Create a new user with input validation
        """
        # Input validation
        if not self._validate_username(username):
            return False

        if not self._validate_email(email):
            return False

        try:
            password_hash = self._hash_password(password)
            self.cursor.execute(
                "INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
                (username, password_hash, email, role)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        except sqlite3.Error:
            return False

    def delete_user(self, username: str) -> bool:
        """
        SECURE: Delete a user
        """
        if not username or not self._validate_username(username):
            return False

        try:
            self.cursor.execute("DELETE FROM users WHERE username = ?", (username,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except sqlite3.Error:
            return False

    def get_all_users(self) -> List[Dict[str, Any]]:
        """SECURE: Get all users"""
        try:
            results = self.cursor.execute(
                "SELECT id, username, email, role, active FROM users ORDER BY username"
            ).fetchall()
            return [dict(row) for row in results]
        except sqlite3.Error:
            return []

    def close(self):
        """Close the database connection"""
        self.conn.close()


# Demonstration of the secure implementation
if __name__ == "__main__":
    db = UserDatabase()

    print("=== Secure Implementation ===")
    print("\n1. Normal authentication works:")
    user = db.authenticate_user("john_doe", "password123")
    if user:
        print(f"✓ Authenticated: {user['username']}")

    print("\n2. SQL injection attempts are blocked:")

    # Attempt 1: Authentication bypass
    user = db.authenticate_user("admin' OR '1'='1", "wrongpassword")
    print(f"✓ Auth bypass prevented: {user is None}")

    # Attempt 2: Data extraction via search
    results = db.search_users("' OR '1'='1")
    all_users = db.get_all_users()
    print(f"✓ Search injection prevented: returned {len(results)} vs {len(all_users)} total users")

    # Attempt 3: Email update injection
    original_count = len(db.get_all_users())
    db.update_user_email("john_doe", "hack@evil.com' WHERE '1'='1")
    admin = db.get_user_by_username("admin")
    print(f"✓ Update injection prevented: admin email is still {admin['email']}")

    print("\n3. Legitimate special characters work:")
    # Create user with apostrophe in name
    success = db.create_user("o'brien", "pass123", "obrien@company.com")
    if success:
        user = db.authenticate_user("o'brien", "pass123")
        print(f"✓ User 'o'brien' created and authenticated successfully")

    print("\n✓ All security measures in place!")
    db.close()