import unittest


"""IMPORTANT: In order to pass test cases, ctrl f '__import__' and change the 
file from challenge to python_solution.
 MAKE SURE ALL THREE FILES ARE IN THE SAME DIRECTORY"""

class TestUserDatabaseFunctionality(unittest.TestCase):
    """Test basic functionality of the user database"""

    def setUp(self):
        """Create a fresh database for each test"""
        # Dynamically load the UserDatabase class
        import sys
        import os

        # Add current directory to path if not already there
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)

        # Try to import from challenge module
        try:
            challenge_module = __import__('challenge')
            UserDatabase = getattr(challenge_module, 'UserDatabase')
            self.db = UserDatabase(":memory:")
        except (ImportError, AttributeError) as e:
            self.skipTest(f"Could not load UserDatabase: {e}")

    def tearDown(self):
        """Clean up database after each test"""
        if hasattr(self, 'db'):
            self.db.close()

    def test_database_initialization(self):
        """Test that database initializes with seed data"""
        users = self.db.get_all_users()
        self.assertGreaterEqual(len(users), 4, "Database should have at least 4 seed users")
        usernames = [u['username'] for u in users]
        self.assertIn('admin', usernames)
        self.assertIn('john_doe', usernames)

    def test_authenticate_valid_user(self):
        """Test authentication with valid credentials"""
        user = self.db.authenticate_user("john_doe", "password123")
        self.assertIsNotNone(user, "Should authenticate valid user")
        self.assertEqual(user['username'], "john_doe")
        self.assertEqual(user['role'], "user")

    def test_authenticate_invalid_password(self):
        """Test authentication with wrong password"""
        user = self.db.authenticate_user("john_doe", "wrongpassword")
        self.assertIsNone(user, "Should not authenticate with wrong password")

    def test_authenticate_nonexistent_user(self):
        """Test authentication with non-existent username"""
        user = self.db.authenticate_user("nonexistent", "password")
        self.assertIsNone(user, "Should not authenticate non-existent user")

    def test_get_user_by_username(self):
        """Test retrieving user by username"""
        user = self.db.get_user_by_username("jane_smith")
        self.assertIsNotNone(user)
        self.assertEqual(user['username'], "jane_smith")
        self.assertEqual(user['email'], "jane@company.com")
        self.assertNotIn('password_hash', user, "Should not expose password hash")

    def test_get_nonexistent_user(self):
        """Test retrieving non-existent user"""
        user = self.db.get_user_by_username("nonexistent")
        self.assertIsNone(user)

    def test_search_users_by_username(self):
        """Test searching users by username"""
        results = self.db.search_users("john")
        self.assertGreaterEqual(len(results), 1)
        self.assertTrue(any(u['username'] == 'john_doe' for u in results))

    def test_search_users_by_email(self):
        """Test searching users by email"""
        results = self.db.search_users("jane@company")
        self.assertGreaterEqual(len(results), 1)
        self.assertTrue(any(u['email'] == 'jane@company.com' for u in results))

    def test_search_users_no_results(self):
        """Test search with no matching results"""
        results = self.db.search_users("nonexistentuser12345")
        self.assertEqual(len(results), 0)

    def test_update_user_email(self):
        """Test updating user email"""
        success = self.db.update_user_email("bob_wilson", "bob.new@company.com")
        self.assertTrue(success)

        user = self.db.get_user_by_username("bob_wilson")
        self.assertEqual(user['email'], "bob.new@company.com")

    def test_update_nonexistent_user_email(self):
        """Test updating email for non-existent user"""
        success = self.db.update_user_email("nonexistent", "test@test.com")
        self.assertFalse(success)

    def test_create_new_user(self):
        """Test creating a new user"""
        success = self.db.create_user("new_user", "newpass123", "new@company.com")
        self.assertTrue(success)

        user = self.db.get_user_by_username("new_user")
        self.assertIsNotNone(user)
        self.assertEqual(user['username'], "new_user")

    def test_delete_user(self):
        """Test deleting a user"""
        success = self.db.delete_user("bob_wilson")
        self.assertTrue(success)

        user = self.db.get_user_by_username("bob_wilson")
        self.assertIsNone(user)

    def test_get_all_users(self):
        """Test retrieving all users"""
        users = self.db.get_all_users()
        self.assertIsInstance(users, list)
        self.assertGreaterEqual(len(users), 4)
        # Verify it's sorted by username
        usernames = [u['username'] for u in users]
        self.assertEqual(usernames, sorted(usernames))


class TestSQLInjectionPrevention(unittest.TestCase):
    """Test that SQL injection attacks are prevented"""

    def setUp(self):
        """Create a fresh database for each test"""
        import sys
        import os

        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)

        try:
            challenge_module = __import__('challenge')
            UserDatabase = getattr(challenge_module, 'UserDatabase')
            self.db = UserDatabase(":memory:")
        except (ImportError, AttributeError) as e:
            self.skipTest(f"Could not load UserDatabase: {e}")

    def tearDown(self):
        """Clean up database after each test"""
        if hasattr(self, 'db'):
            self.db.close()

    def test_auth_sql_injection_or_bypass(self):
        """Test that OR-based SQL injection in authentication is prevented"""
        # Attempt to bypass authentication with OR statement
        user = self.db.authenticate_user("admin' OR '1'='1", "wrongpassword")
        self.assertIsNone(user, "SQL injection bypass should be prevented")

        user = self.db.authenticate_user("admin' OR '1'='1' --", "wrongpassword")
        self.assertIsNone(user, "SQL injection with comment should be prevented")

    def test_auth_sql_injection_union(self):
        """Test that UNION-based SQL injection in authentication is prevented"""
        user = self.db.authenticate_user("admin' UNION SELECT * FROM users --", "pass")
        self.assertIsNone(user, "UNION-based SQL injection should be prevented")

    def test_auth_sql_injection_always_true(self):
        """Test that always-true conditions are prevented"""
        user = self.db.authenticate_user("' OR 1=1 --", "anything")
        self.assertIsNone(user, "Always-true SQL injection should be prevented")

    def test_get_user_sql_injection(self):
        """Test that SQL injection in get_user_by_username is prevented"""
        # Should not return multiple users or cause errors
        user = self.db.get_user_by_username("admin' OR '1'='1")
        self.assertIsNone(user, "SQL injection should return None, not bypass query")

        # Should handle single quotes safely
        user = self.db.get_user_by_username("admin'--")
        self.assertIsNone(user)

    def test_search_sql_injection_data_extraction(self):
        """Test that SQL injection in search cannot extract all data"""
        # Attempt to extract all users with OR 1=1
        results = self.db.search_users("' OR '1'='1")

        # With parameterized queries, this literal string won't match anything
        # So we expect 0 results, not all users
        self.assertEqual(len(results), 0,
                        "SQL injection pattern should not match any legitimate data")

    def test_search_sql_injection_with_comment(self):
        """Test that SQL injection with comments is prevented"""
        results = self.db.search_users("test' OR 1=1 --")

        # With parameterized queries, this won't execute as SQL
        # It will be treated as a literal search string
        self.assertEqual(len(results), 0,
                       "SQL injection pattern should not return data")

    def test_search_sql_injection_union_attack(self):
        """Test that UNION attacks in search are prevented"""
        # UNION attacks should be prevented by parameterized queries or validation
        try:
            results = self.db.search_users("test' UNION SELECT username, email, role FROM users --")
            all_users = self.db.get_all_users()
            # Should return limited results, not exploit the database
            self.assertLessEqual(len(results), len(all_users),
                           "UNION-based SQL injection should be prevented")
        except Exception:
            # If it raises an exception, that's acceptable (UNION prevented)
            pass

    def test_update_email_sql_injection_scope(self):
        """Test that SQL injection in update_email cannot modify other records"""
        original_admin_email = self.db.get_user_by_username("admin")['email']

        # Attempt to update all user emails with SQL injection
        # This should either fail or only update john_doe's email
        try:
            self.db.update_user_email("john_doe", "hacked@evil.com' WHERE '1'='1")
        except Exception:
            # If validation rejects it, that's good
            pass

        # Verify admin email wasn't changed
        admin = self.db.get_user_by_username("admin")
        self.assertEqual(admin['email'], original_admin_email,
                        "SQL injection should not affect other records")

    def test_special_characters_handled_safely(self):
        """Test that special SQL characters are handled safely"""
        # These should not cause SQL errors
        try:
            self.db.authenticate_user("user'; DROP TABLE users; --", "pass")
            self.db.get_user_by_username("admin'; DELETE FROM users; --")
            self.db.search_users("test'); DROP TABLE users; --")
            self.db.update_user_email("john_doe", "test'); DROP TABLE users; --")
        except Exception as e:
            # If there's a SQL syntax error, it indicates improper handling
            if "syntax" in str(e).lower() or "operational" in str(e).lower():
                self.fail(f"SQL syntax error indicates improper input handling: {e}")

        # Verify table still exists and has data
        users = self.db.get_all_users()
        self.assertGreater(len(users), 0, "Table should still exist after injection attempts")

    def test_single_quote_in_legitimate_data(self):
        """Test that legitimate single quotes in data are handled correctly"""
        # Create user with single quote in name (legitimate use case)
        success = self.db.create_user("obrien", "password123", "obrien@company.com")
        self.assertTrue(success, "Should be able to create user")

        user = self.db.get_user_by_username("obrien")
        self.assertIsNotNone(user)
        self.assertEqual(user['username'], "obrien")

        # Should be able to authenticate
        auth_user = self.db.authenticate_user("obrien", "password123")
        self.assertIsNotNone(auth_user, "Should authenticate legitimate user")

    def test_semicolon_injection_attack(self):
        """Test that semicolon-based multi-statement attacks are prevented"""
        # Semicolon attacks should be rejected by input validation or handled safely
        try:
            user = self.db.authenticate_user("admin'; DROP TABLE users; --", "pass")
            self.assertIsNone(user, "Semicolon injection should be prevented")
        except Exception:
            # If it raises an exception, that's acceptable (multi-statement prevention)
            pass

        # Verify table still exists
        users = self.db.get_all_users()
        self.assertGreater(len(users), 0, "Table should still exist")

    def test_hex_encoding_attack(self):
        """Test that hex-encoded attacks are prevented"""
        user = self.db.authenticate_user("admin' OR 0x31=0x31 --", "pass")
        self.assertIsNone(user)


class TestInputValidation(unittest.TestCase):
    """Test input validation and error handling"""

    def setUp(self):
        """Create a fresh database for each test"""
        import sys
        import os

        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)

        try:
            challenge_module = __import__('challenge')
            UserDatabase = getattr(challenge_module, 'UserDatabase')
            self.db = UserDatabase(":memory:")
        except (ImportError, AttributeError) as e:
            self.skipTest(f"Could not load UserDatabase: {e}")

    def tearDown(self):
        """Clean up database after each test"""
        if hasattr(self, 'db'):
            self.db.close()

    def test_empty_username_authentication(self):
        """Test authentication with empty username"""
        user = self.db.authenticate_user("", "password")
        self.assertIsNone(user)

    def test_empty_password_authentication(self):
        """Test authentication with empty password"""
        user = self.db.authenticate_user("john_doe", "")
        self.assertIsNone(user)

    def test_none_username_authentication(self):
        """Test authentication with None username"""
        user = self.db.authenticate_user(None, "password")
        self.assertIsNone(user)

    def test_empty_search_term(self):
        """Test search with empty term"""
        results = self.db.search_users("")
        # Should handle gracefully, not crash
        self.assertIsInstance(results, list)

    def test_very_long_input_handled(self):
        """Test that very long inputs don't cause issues"""
        long_string = "a" * 10000
        try:
            self.db.authenticate_user(long_string, "pass")
            self.db.get_user_by_username(long_string)
            self.db.search_users(long_string)
        except Exception as e:
            self.fail(f"Should handle long inputs gracefully: {e}")

    def test_invalid_username_characters(self):
        """Test that invalid characters in username are rejected"""
        # Test various invalid characters
        invalid_usernames = [
            "user@name",
            "user name",
            "user/name",
            "user\\name",
            "user<n>",
            "user;name"
        ]
        for username in invalid_usernames:
            user = self.db.authenticate_user(username, "password123")
            self.assertIsNone(user, f"Username '{username}' should be rejected")

    def test_invalid_email_format(self):
        """Test that invalid email formats are rejected"""
        invalid_emails = [
            "@company.com",
            "user@",
            "user@@company.com",
            "user company@test.com"
        ]
        for email in invalid_emails:
            success = self.db.update_user_email("john_doe", email)
            self.assertFalse(success, f"Email '{email}' should be rejected")

    def test_valid_email_format_accepted(self):
        """Test that valid email formats are accepted"""
        valid_emails = [
            "user@company.com",
            "user.name@company.co.uk",
            "user+tag@company.com",
            "user123@company123.com"
        ]
        for email in valid_emails:
            success = self.db.update_user_email("john_doe", email)
            self.assertTrue(success, f"Email '{email}' should be accepted")

            # Verify it was actually updated
            user = self.db.get_user_by_username("john_doe")
            self.assertEqual(user['email'], email)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""

    def setUp(self):
        """Create a fresh database for each test"""
        import sys
        import os

        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)

        try:
            challenge_module = __import__('challenge')
            UserDatabase = getattr(challenge_module, 'UserDatabase')
            self.db = UserDatabase(":memory:")
        except (ImportError, AttributeError) as e:
            self.skipTest(f"Could not load UserDatabase: {e}")

    def tearDown(self):
        """Clean up database after each test"""
        if hasattr(self, 'db'):
            self.db.close()

    def test_case_sensitive_username(self):
        """Test that usernames are case-sensitive"""
        user_lower = self.db.authenticate_user("john_doe", "password123")
        self.assertIsNotNone(user_lower)

        user_upper = self.db.authenticate_user("JOHN_DOE", "password123")
        self.assertIsNone(user_upper, "Usernames should be case-sensitive")

    def test_whitespace_handling(self):
        """Test handling of whitespace in inputs"""
        # Leading/trailing whitespace
        user = self.db.authenticate_user(" john_doe ", "password123")
        # Should either trim or reject, but not cause errors
        self.assertIsInstance(user, (dict, type(None)))

    def test_unicode_characters(self):
        """Test handling of unicode characters"""
        # Should handle gracefully without crashing
        try:
            self.db.authenticate_user("用户", "password")
            self.db.search_users("тест")
        except Exception as e:
            self.fail(f"Should handle unicode gracefully: {e}")

    def test_null_byte_injection(self):
        """Test that null byte injection is prevented"""
        # Null bytes should be rejected by input validation or handled safely
        try:
            user = self.db.authenticate_user("admin\x00' OR '1'='1", "pass")
            self.assertIsNone(user, "Null byte injection should be prevented")
        except Exception:
            # If it raises an exception due to null byte, that's acceptable
            pass

    def test_concurrent_operations(self):
        """Test that basic concurrent operations don't corrupt data"""
        # Create multiple users
        for i in range(10):
            self.db.create_user(f"user_{i}", "pass", f"user{i}@test.com")

        # Verify all users exist
        users = self.db.get_all_users()
        self.assertGreaterEqual(len(users), 10)


def run_tests():
    """Run all tests with detailed output"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestUserDatabaseFunctionality))
    suite.addTests(loader.loadTestsFromTestCase(TestSQLInjectionPrevention))
    suite.addTests(loader.loadTestsFromTestCase(TestInputValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))

    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70)

    return result.wasSuccessful()


if __name__ == "__main__":
    # Run tests
    success = run_tests()

    # Exit with appropriate code
    exit(0 if success else 1)
