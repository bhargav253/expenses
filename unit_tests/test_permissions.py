#!/usr/bin/env python3
"""
Unit test for expense deletion permissions
This test will show the debug print statements from app.py
"""

import sys
import os
import unittest
from datetime import datetime

# Add the parent directory to Python path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models import User, Dashboard, DashboardMember, Expense, UserDashboardSettings

class TestExpensePermissions(unittest.TestCase):
    
    def setUp(self):
        """Set up test database and test data"""
        # Use an in-memory SQLite database for testing
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        
        self.app = app.test_client()
        
        with app.app_context():
            db.create_all()
            
            # Store IDs instead of objects to avoid detached instance issues
            # Create test users
            user1 = User(
                email='test1@example.com',
                name='Test User 1',
                username='testuser1'
            )
            user1.set_password('password1')
            
            user2 = User(
                email='test2@example.com',
                name='Test User 2',
                username='testuser2'
            )
            user2.set_password('password2')
            
            db.session.add(user1)
            db.session.add(user2)
            db.session.commit()
            
            self.user1_id = user1.id
            self.user2_id = user2.id
            
            # Create test dashboard
            dashboard = Dashboard(
                name='Test Dashboard',
                description='Test dashboard for permissions',
                created_by=user1.id
            )
            db.session.add(dashboard)
            db.session.commit()
            self.dashboard_id = dashboard.id
            
            # Add both users as members (user1 as owner, user2 as member)
            member1 = DashboardMember(
                dashboard_id=dashboard.id,
                user_id=user1.id,
                role='owner'
            )
            member2 = DashboardMember(
                dashboard_id=dashboard.id,
                user_id=user2.id,
                role='member'
            )
            db.session.add(member1)
            db.session.add(member2)
            db.session.commit()
            
            # Create test expense owned by user1
            expense = Expense(
                dashboard_id=dashboard.id,
                user_id=user1.id,
                date=datetime.now().date(),
                description='Test expense',
                amount=100.00,
                category='misc'
            )
            db.session.add(expense)
            db.session.commit()
            self.expense_id = expense.id
            
            # Set user1 to private mode (default)
            settings1 = UserDashboardSettings(
                user_id=user1.id,
                dashboard_id=dashboard.id,
                edit_mode='private'
            )
            db.session.add(settings1)
            db.session.commit()
    
    def tearDown(self):
        """Clean up after tests"""
        with app.app_context():
            db.session.remove()
            db.drop_all()
    
    def test_delete_expense_permission_denied(self):
        """Test that user2 cannot delete user1's expense when user1 has private mode"""
        print("\n" + "="*60)
        print("TEST: User2 trying to delete User1's expense (private mode)")
        print("="*60)
        
        with app.app_context():
            # Simulate user2 session
            with self.app.session_transaction() as sess:
                sess['user_id'] = self.user2_id
            
            # Make DELETE request
            response = self.app.delete(f'/api/dashboard/{self.dashboard_id}/expenses/{self.expense_id}')
            
            print(f"Response status: {response.status_code}")
            print(f"Response data: {response.get_json()}")
            
            # Should be 403 Forbidden
            self.assertEqual(response.status_code, 403)
            self.assertIn('private mode', response.get_json()['error'].lower())
    
    def test_delete_expense_permission_granted(self):
        """Test that user1 can delete their own expense"""
        print("\n" + "="*60)
        print("TEST: User1 deleting their own expense")
        print("="*60)
        
        with app.app_context():
            # Simulate user1 session
            with self.app.session_transaction() as sess:
                sess['user_id'] = self.user1_id
            
            # Make DELETE request
            response = self.app.delete(f'/api/dashboard/{self.dashboard_id}/expenses/{self.expense_id}')
            
            print(f"Response status: {response.status_code}")
            print(f"Response data: {response.get_json()}")
            
            # Should be successful
            self.assertEqual(response.status_code, 200)
            self.assertIn('successfully', response.get_json()['message'].lower())
    
    def test_delete_expense_public_mode(self):
        """Test that user2 can delete user1's expense when user1 has public mode"""
        print("\n" + "="*60)
        print("TEST: User2 deleting User1's expense (public mode)")
        print("="*60)
        
        with app.app_context():
            # Change user1 to public mode
            settings = UserDashboardSettings.query.filter_by(
                user_id=self.user1_id,
                dashboard_id=self.dashboard_id
            ).first()
            settings.edit_mode = 'public'
            db.session.commit()
            
            # Create a new expense for this test
            expense2 = Expense(
                dashboard_id=self.dashboard_id,
                user_id=self.user1_id,
                date=datetime.now().date(),
                description='Test expense for public mode',
                amount=50.00,
                category='misc'
            )
            db.session.add(expense2)
            db.session.commit()
            expense2_id = expense2.id
            
            # Simulate user2 session
            with self.app.session_transaction() as sess:
                sess['user_id'] = self.user2_id
            
            # Make DELETE request
            response = self.app.delete(f'/api/dashboard/{self.dashboard_id}/expenses/{expense2_id}')
            
            print(f"Response status: {response.status_code}")
            print(f"Response data: {response.get_json()}")
            
            # Should be successful when in public mode
            self.assertEqual(response.status_code, 200)
            self.assertIn('successfully', response.get_json()['message'].lower())

if __name__ == '__main__':
    print("Running expense permission tests...")
    print("This will show the debug print statements from app.py")
    print()
    
    # Run the tests
    unittest.main(verbosity=2)
