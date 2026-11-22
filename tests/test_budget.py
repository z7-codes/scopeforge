import unittest

from scopeforge.budget import Budget
from scopeforge.errors import BudgetExhausted


class BudgetTests(unittest.TestCase):
    def test_global_limit(self):
        budget = Budget(max_requests=2, delay=0)
        budget.spend("a")
        budget.spend("b")
        with self.assertRaises(BudgetExhausted):
            budget.spend("c")

    def test_per_host_limit(self):
        budget = Budget(max_requests=10, max_per_host=1, delay=0)
        budget.spend("a")
        with self.assertRaises(BudgetExhausted):
            budget.spend("a")

    def test_remaining_and_snapshot(self):
        budget = Budget(max_requests=3, delay=0)
        self.assertEqual(budget.remaining(), 3)
        budget.spend("a")
        self.assertEqual(budget.remaining(), 2)
        snapshot = budget.snapshot()
        self.assertEqual(snapshot["sent"], 1)
        self.assertEqual(snapshot["per_host"], {"a": 1})


if __name__ == "__main__":
    unittest.main()
