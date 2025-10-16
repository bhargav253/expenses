#!/usr/bin/env python3
"""
Debug script to check what happens during an actual delete request
"""

import sys
import os

# Add the parent directory to Python path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models import User, Expense

def debug_live_delete():
    """Debug what happens during an actual delete request"""
    with app.app_context():
        print("=== DEBUG LIVE DELETE SCENARIO ===")
        
        # Simulate what happens when Sample User tries to delete expense 162
        sample_user = User.query.filter_by(name='Sample User').first()
        expense_162 = Expense.query.get(162)
        
        print(f"Sample User: ID={sample_user.id}, Name={sample_user.name}")
        print(f"Expense 162: ID={expense_162.id}, User ID={expense_162.user_id}, Owner={User.query.get(expense_162.user_id).name}")
        
        print(f"\n--- PERMISSION CHECK ---")
        print(f"Sample User ID: {sample_user.id}")
        print(f"Expense Owner ID: {expense_162.user_id}")
        print(f"Are they the same? {sample_user.id == expense_162.user_id}")
        
        # Check what the session would contain
        print(f"\n--- SESSION SIMULATION ---")
        print("If Sample User is logged in, session['user_id'] should be: 3")
        print("If Test User is logged in, session['user_id'] would be: 1")
        
        # Check dashboard membership
        from models import DashboardMember
        dashboard_members = DashboardMember.query.filter_by(dashboard_id=expense_162.dashboard_id).all()
        print(f"\n--- DASHBOARD MEMBERS (Dashboard ID: {expense_162.dashboard_id}) ---")
        for member in dashboard_members:
            user = User.query.get(member.user_id)
            print(f"User: {user.name} (ID: {user.id}), Role: {member.role}")
        
        # Check user settings
        from models import UserDashboardSettings
        expense_owner_settings = UserDashboardSettings.query.filter_by(
            user_id=expense_162.user_id,
            dashboard_id=expense_162.dashboard_id
        ).first()
        
        print(f"\n--- EXPENSE OWNER SETTINGS ---")
        if expense_owner_settings:
            print(f"Test User (owner) edit mode: {expense_owner_settings.edit_mode}")
        else:
            print("No settings found for expense owner")
        
        sample_user_settings = UserDashboardSettings.query.filter_by(
            user_id=sample_user.id,
            dashboard_id=expense_162.dashboard_id
        ).first()
        
        print(f"\n--- SAMPLE USER SETTINGS ---")
        if sample_user_settings:
            print(f"Sample User edit mode: {sample_user_settings.edit_mode}")
        else:
            print("No settings found for Sample User")
        
        print(f"\n--- EXPECTED BEHAVIOR ---")
        print("If Sample User (ID:3) tries to delete Test User's (ID:1) expense:")
        print("1. Check if Sample User is member of dashboard: YES")
        print("2. Check expense owner settings: Test User has private mode")
        print("3. Check if current user == expense owner: NO (3 != 1)")
        print("4. Result: PERMISSION DENIED (403)")
        
        print(f"\n--- ACTUAL TEST ---")
        # Simulate the permission check
        if expense_owner_settings and expense_owner_settings.edit_mode == 'private' and expense_162.user_id != sample_user.id:
            print("PERMISSION DENIED: Expense owner has private mode and current user is not the owner")
        else:
            print("PERMISSION GRANTED: Allowing delete operation")

if __name__ == '__main__':
    debug_live_delete()
