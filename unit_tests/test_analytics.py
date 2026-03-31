#!/usr/bin/env python3
"""Unit tests for expense analytics workflow responses."""

import os
import sys
import unittest
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db  # noqa: E402
from models import User, Dashboard, DashboardMember, Expense  # noqa: E402

class TestAnalyticsEndpoint(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()

        with app.app_context():
            user = User.query.filter_by(email='trial@example.com').first()
            if not user:
                raise unittest.SkipTest("Existing user trial@example.com not found; ensure DB is seeded with this user.")

            self.user_id = user.id

            # Create an isolated dashboard for this test under the existing user
            dashboard = Dashboard(
                name='Analytics Test Dashboard',
                description='Temp dashboard for analytics unit test',
                created_by=user.id
            )
            db.session.add(dashboard)
            db.session.commit()
            self.dashboard_id = dashboard.id

            # Membership (owner)
            member = DashboardMember(
                dashboard_id=dashboard.id,
                user_id=user.id,
                role='owner'
            )
            db.session.add(member)

            # Expenses: rent in 2019 + comparison data in 2024
            expenses = [
                Expense(
                    dashboard_id=dashboard.id,
                    user_id=user.id,
                    date=date(2019, 1, 15),
                    description='January rent',
                    amount=100.00,
                    category='rent'
                ),
                Expense(
                    dashboard_id=dashboard.id,
                    user_id=user.id,
                    date=date(2019, 2, 15),
                    description='February rent',
                    amount=150.00,
                    category='rent'
                ),
                Expense(
                    dashboard_id=dashboard.id,
                    user_id=user.id,
                    date=date(2019, 3, 15),
                    description='March rent',
                    amount=200.00,
                    category='rent'
                ),
                Expense(
                    dashboard_id=dashboard.id,
                    user_id=user.id,
                    date=date(2021, 1, 10),
                    description='Groceries noise',
                    amount=50.00,
                    category='grocery'
                ),
                Expense(
                    dashboard_id=dashboard.id,
                    user_id=user.id,
                    date=date(2024, 1, 2),
                    description='January groceries',
                    amount=300.00,
                    category='grocery'
                ),
                Expense(
                    dashboard_id=dashboard.id,
                    user_id=user.id,
                    date=date(2024, 1, 10),
                    description='January restaurant',
                    amount=120.00,
                    category='restaurant'
                ),
                Expense(
                    dashboard_id=dashboard.id,
                    user_id=user.id,
                    date=date(2024, 2, 3),
                    description='February groceries',
                    amount=210.00,
                    category='grocery'
                ),
                Expense(
                    dashboard_id=dashboard.id,
                    user_id=user.id,
                    date=date(2024, 2, 18),
                    description='February restaurant',
                    amount=260.00,
                    category='restaurant'
                ),
                Expense(
                    dashboard_id=dashboard.id,
                    user_id=user.id,
                    date=date(2024, 1, 6),
                    description='January shopping',
                    amount=90.00,
                    category='shopping'
                ),
                Expense(
                    dashboard_id=dashboard.id,
                    user_id=user.id,
                    date=date(2024, 2, 6),
                    description='February shopping',
                    amount=140.00,
                    category='shopping'
                ),
                Expense(
                    dashboard_id=dashboard.id,
                    user_id=user.id,
                    date=date(2024, 1, 8),
                    description='January utility',
                    amount=180.00,
                    category='utility'
                ),
                Expense(
                    dashboard_id=dashboard.id,
                    user_id=user.id,
                    date=date(2024, 2, 8),
                    description='February utility',
                    amount=175.00,
                    category='utility'
                )
            ]
            db.session.add_all(expenses)
            db.session.commit()
            self._created_expense_ids = [e.id for e in expenses]
            self._member_id = member.id

    def tearDown(self):
        with app.app_context():
            # Clean up created data without dropping user or tables
            if getattr(self, "_created_expense_ids", None):
                Expense.query.filter(Expense.id.in_(self._created_expense_ids)).delete(synchronize_session=False)
            if getattr(self, "_member_id", None):
                DashboardMember.query.filter_by(id=self._member_id).delete()
            if getattr(self, "dashboard_id", None):
                Dashboard.query.filter_by(id=self.dashboard_id).delete()
            db.session.commit()

    def test_analytics_rent_2019(self):
        prompt = "Plot the rent for the months of 2019"

        # Simulate logged-in session
        with self.app.session_transaction() as sess:
            sess['user_id'] = self.user_id

        # Call analytics endpoint
        resp = self.app.post(
            f'/api/dashboard/{self.dashboard_id}/analytics/query',
            json={'prompt': prompt}
        )

        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        data = resp.get_json()

        # Expected: bar trend by month, filtered to 2019 rent
        self.assertEqual(data['chart_type'], 'bar')
        self.assertEqual(data['workflow'], 'category_trend')
        self.assertEqual(data['labels'], ['2019-01', '2019-02', '2019-03'])

        self.assertEqual(len(data['data']), 3)
        returned = dict(zip(data['labels'], data['data']))
        self.assertAlmostEqual(returned.get('2019-01', 0), 100.00, places=2)
        self.assertAlmostEqual(returned.get('2019-02', 0), 150.00, places=2)
        self.assertAlmostEqual(returned.get('2019-03', 0), 200.00, places=2)
        self.assertIn('rent', data.get('summary', '').lower())

    def test_compare_restaurant_vs_grocery_2024(self):
        prompt = "compare restaurant expense with grovery expense in 2024"

        with self.app.session_transaction() as sess:
            sess['user_id'] = self.user_id

        resp = self.app.post(
            f'/api/dashboard/{self.dashboard_id}/analytics/query',
            json={'prompt': prompt}
        )

        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        data = resp.get_json()

        self.assertEqual(data['workflow'], 'category_vs_category')
        self.assertEqual(data['chart_type'], 'line')
        self.assertEqual(data['labels'], ['2024-01', '2024-02'])
        self.assertIn('datasets', data)
        self.assertEqual(len(data['datasets']), 2)
        self.assertEqual(data['datasets'][0]['label'], 'Restaurant')
        self.assertEqual(data['datasets'][1]['label'], 'Grocery')
        self.assertEqual(data['datasets'][0]['data'], [120.0, 260.0])
        self.assertEqual(data['datasets'][1]['data'], [300.0, 210.0])
        self.assertIn('2024', data.get('summary', ''))
        self.assertTrue(any('typo' in warning.lower() or 'one category' not in warning.lower() for warning in data.get('critic', {}).get('warnings', [''])))

    def test_typo_category_compare_routes_correctly(self):
        prompt = "compare resturant expense with grocery expense in 2024"

        with self.app.session_transaction() as sess:
            sess['user_id'] = self.user_id

        resp = self.app.post(
            f'/api/dashboard/{self.dashboard_id}/analytics/query',
            json={'prompt': prompt}
        )

        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        data = resp.get_json()
        self.assertEqual(data['workflow'], 'category_vs_category')
        self.assertIn('warnings', data.get('critic', {}))
        self.assertTrue(any('typo-tolerant' in warning.lower() for warning in data['critic']['warnings']))

    def test_what_changed_workflow(self):
        prompt = "what changed from january 2024 to february 2024"

        with self.app.session_transaction() as sess:
            sess['user_id'] = self.user_id

        resp = self.app.post(
            f'/api/dashboard/{self.dashboard_id}/analytics/query',
            json={'prompt': prompt}
        )

        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        data = resp.get_json()
        self.assertEqual(data['workflow'], 'what_changed')
        self.assertEqual(data['chart_type'], 'table')
        self.assertIn('rows', data)

    def test_monthly_review_workflow(self):
        prompt = "give me a monthly review for january 2024"

        with self.app.session_transaction() as sess:
            sess['user_id'] = self.user_id

        resp = self.app.post(
            f'/api/dashboard/{self.dashboard_id}/analytics/query',
            json={'prompt': prompt}
        )

        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        data = resp.get_json()
        self.assertEqual(data['workflow'], 'monthly_review')
        self.assertEqual(data['chart_type'], 'table')
        self.assertIn('artifacts', data)

    def test_follow_up_adds_categories_to_existing_plot(self):
        with self.app.session_transaction() as sess:
            sess['user_id'] = self.user_id

        first = self.app.post(
            f'/api/dashboard/{self.dashboard_id}/analytics/query',
            json={'prompt': 'plot grocery and restaurant expenses in the months of 2024 using a line plot'}
        )
        self.assertEqual(first.status_code, 200, first.get_data(as_text=True))
        first_data = first.get_json()
        self.assertEqual(first_data['workflow'], 'category_vs_category')
        self.assertEqual(first_data['chart_type'], 'line')
        self.assertIn('session_id', first_data)

        second = self.app.post(
            f'/api/dashboard/{self.dashboard_id}/analytics/query',
            json={
                'prompt': 'can you also add shopping and utility expenses to the plot',
                'session_id': first_data['session_id'],
            }
        )
        self.assertEqual(second.status_code, 200, second.get_data(as_text=True))
        second_data = second.get_json()
        self.assertEqual(second_data['workflow'], 'category_vs_category')
        self.assertEqual(second_data['chart_type'], 'line')
        self.assertEqual(second_data['labels'], ['2024-01', '2024-02'])
        self.assertEqual(len(second_data['datasets']), 4)
        labels = [dataset['label'] for dataset in second_data['datasets']]
        self.assertEqual(labels, ['Grocery', 'Restaurant', 'Shopping', 'Utility'])
        self.assertTrue(any('follow-up request merged' in warning.lower() for warning in second_data.get('critic', {}).get('warnings', [])))


if __name__ == '__main__':
    unittest.main()
