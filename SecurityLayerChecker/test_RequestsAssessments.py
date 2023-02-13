import unittest
import time

from SecurityLayerChecker.SecurityLayerChecker import RequestsAssessments


class TestRequestsAssessments(unittest.TestCase):
    def setUp(self):
        self.requests_assessments = RequestsAssessments()

    def test_total_requests(self):
        self.assertEqual(self.requests_assessments.total_requests(), 0)
        self.requests_assessments.add_request(1, time.time())
        self.assertEqual(self.requests_assessments.total_requests(), 1)
        self.requests_assessments.add_request(2, time.time())
        self.assertEqual(self.requests_assessments.total_requests(), 2)

    def test_add_request(self):
        self.requests_assessments.add_request(1, time.time())
        self.assertEqual(self.requests_assessments.total_requests(), 1)
        self.requests_assessments.add_request(1, time.time())
        self.assertEqual(self.requests_assessments.total_requests(), 1)

    def test_get_last_time(self):
        self.assertEqual(self.requests_assessments.get_last_time(), 0.0)
        self.requests_assessments.add_request(1, time.time())
        last_time = self.requests_assessments.get_last_time()
        self.assertIsInstance(last_time, float)

    def test_remove_request(self):
        self.requests_assessments.add_request(1, time.time())
        self.requests_assessments.remove_request(1)
        self.assertEqual(self.requests_assessments.total_requests(), 0)

    def test_are_there_requests(self):
        self.assertFalse(self.requests_assessments.are_there_requests())
        self.requests_assessments.add_request(1, time.time())
        self.assertTrue(self.requests_assessments.are_there_requests())

    def test_get_seconds_to_wait(self):
        self.assertEqual(self.requests_assessments.get_seconds_to_wait(), 10)
        self.requests_assessments.add_request(1, time.time())
        time.sleep(2)
        self.assertTrue(self.requests_assessments.get_seconds_to_wait() < 10)


if __name__ == '__main__':
    unittest.main()
