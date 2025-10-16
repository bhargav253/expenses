#!/usr/bin/env python3
"""
Debug script to check why user IDs are matching incorrectly
"""

import sys
import os

# Add the parent directory to Python path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models import User, Expense, DashboardMember, UserDashboardSettings

def debug_user_matching():
    """Debug why user IDs are matching incorrectly"""
    with app.app_context():
        print("=== DEBUG USER MATCHING ===")
        
        # Get all users
        users = User.query.all()
        print("\n--- ALL USERS ---")
        for user in users:
            print(f"User ID: {user.id}, Name: {user.name}, Email: {user.email}")
        
        # Get all expenses
        expenses = Expense.query.all()
        print("\n--- ALL EXPENSES ---")
        for expense in expenses:
            user = User.query.get(expense.user_id)
            print(f"Expense ID: {expense.id}, User ID: {expense.user_id}, User Name: {user.name if user else 'Unknown'}, Description: {expense.description}")
        
        # Get all dashboard members
        members = DashboardMember.query.all()
        print("\n--- ALL DASHBOARD MEMBERS ---")
        for member in members:
            user = User.query.get(member.user_id)
            dashboard = member.dashboard
            print(f"Dashboard: {dashboard.name}, User: {user.name}, Role: {member.role}")
        
        # Get all user dashboard settings
        settings = UserDashboardSettings.query.all()
        print("\n--- ALL USER DASHBOARD SETTINGS ---")
        for setting in settings:
            user = User.query.get(setting.user_id)
            dashboard = setting.dashboard
            print(f"Dashboard: {dashboard.name}, User: {user.name}, Edit Mode: {setting.edit_mode}")
        
        print("\n=== SPECIFIC DEBUG FOR EXPENSE 162 ===")
        expense_162 = Expense.query.get(162)
        if expense_162:
            print(f"Expense 162 details:")
            print(f"  - ID: {expense_162.id}")
            print(f"  - User ID: {expense_162.user_id}")
            print(f"  - Dashboard ID: {expense_162.dashboard_id}")
            print(f"  - Description: {expense_162.description}")
            
            owner = User.query.get(expense_162.user_id)
            print(f"  - Owner: {owner.name if owner else 'Unknown'}")
            
            # Check current session user (Sample User)
            sample_user = User.query.filter_by(name='Sample User').first()
            if sample_user:
                print(f"  - Sample User ID: {sample_user.id}")
                print(f"  - Sample User Name: {sample_user.name}")
                print(f"  - Match Status: {'MATCHES' if sample_user.id == expense_162.user_id else 'DOES NOT MATCH'}")
        
        print("\n=== SESSION DEBUG ===")
        # This would need to be run in the context of an actual request
        # For now, let's check what users exist
        sample_user = User.query.filter_by(name='Sample User').first()
        test_user = User.query.filter_by(name='Test User').first()
        
        if sample_user and test_user:
            print(f"Sample User ID: {sample_user.id}")
            print(f"Test User ID: {test_user.id}")
            print(f"Are they the same? {sample_user.id == test_user.id}")

if __name__ == '__main__':
    debug_user_matching()
