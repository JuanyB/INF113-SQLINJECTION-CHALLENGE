"""
SQL Injection Prevention Challenge - STARTER CODE
==================================================

SCENARIO:
You've inherited a user management system for a small company. The system works
functionally, but a security audit has revealed critical SQL injection vulnerabilities.
Your task is to fix these vulnerabilities while maintaining all existing functionality.

OBJECTIVE:
Fix the SQL injection vulnerabilities in this code by implementing parameterized queries
and proper input validation, while ensuring all existing features continue to work.

REQUIREMENTS:
1. Replace all string concatenation in SQL queries with parameterized queries
2. Add input validation for usernames and emails
3. Implement proper error handling for database operations
4. Ensure all test cases pass after your modifications

VULNERABLE AREAS TO FIX:
- authenticate_user() function
- get_user_by_username() function
- search_users() function
- update_user_email() function
"""

import sqlite3
import hashlib
from typing import Optional, List, Dict, Any


class UserDatabase:
    """A user management system with SQL injection vulnerabilities (VULNERABLE VERSION)"""

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

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        VULNERABLE: Authenticate a user by username and password
        This function is vulnerable to SQL injection!

        TODO: Fix this function to use parameterized queries
        """
        password_hash = self._hash_password(password)
        # VULNERABLE: String concatenation in SQL query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password_hash}' AND active = 1"
        result = self.cursor.execute(query).fetchone()

        if result:
            return dict(result)
        return None

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        VULNERABLE: Retrieve user information by username
        This function is vulnerable to SQL injection!

        TODO: Fix this function to use parameterized queries
        """
        # VULNERABLE: String concatenation in SQL query
        query = f"SELECT id, username, email, role, active FROM users WHERE username = '{username}'"
        result = self.cursor.execute(query).fetchone()

        if result:
            return dict(result)
        return None

    def search_users(self, search_term: str) -> List[Dict[str, Any]]:
        """
        VULNERABLE: Search for users by username or email
        This function is vulnerable to SQL injection!

        TODO: Fix this function to use parameterized queries and proper LIKE syntax
        """
        # VULNERABLE: String concatenation in SQL query with LIKE
        query = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{search_term}%' OR email LIKE '%{search_term}%'"
        results = self.cursor.execute(query).fetchall()

        return [dict(row) for row in results]

    def update_user_email(self, username: str, new_email: str) -> bool:
        """
        VULNERABLE: Update a user's email address
        This function is vulnerable to SQL injection!

        TODO: Fix this function to use parameterized queries and add email validation
        """
        # VULNERABLE: String concatenation in SQL query
        query = f"UPDATE users SET email = '{new_email}' WHERE username = '{username}'"
        self.cursor.execute(query)
        self.conn.commit()

        return self.cursor.rowcount > 0

    def create_user(self, username: str, password: str, email: str, role: str = "user") -> bool:
        """
        SAFE: Create a new user (this function is already secure as an example)
        This demonstrates the correct way to write SQL queries
        """
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

    def delete_user(self, username: str) -> bool:
        """
        SAFE: Delete a user (this function is already secure as an example)
        """
        self.cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        self.conn.commit()
        return self.cursor.rowcount > 0

    def get_all_users(self) -> List[Dict[str, Any]]:
        """SAFE: Get all users (this function is already secure)"""
        results = self.cursor.execute(
            "SELECT id, username, email, role, active FROM users ORDER BY username"
        ).fetchall()
        return [dict(row) for row in results]

    def close(self):
        """Close the database connection"""
        self.conn.close()


# Example usage demonstrating the vulnerabilities
if __name__ == "__main__":
    db = UserDatabase()

    print("=== Normal Usage ===")
    user = db.authenticate_user("john_doe", "password123")
    if user:
        print(f"✓ Authenticated: {user['username']} ({user['role']})")

    print("\n=== SQL Injection Attack Examples ===")
    print("⚠️  These attacks would work on the vulnerable starter code:")
    print("1. Authentication bypass: username = admin' OR '1'='1")
    print("2. Data extraction: search_term = ' OR 1=1 --")
    print("3. Email injection: new_email = test@test.com' WHERE '1'='1")

    db.close()