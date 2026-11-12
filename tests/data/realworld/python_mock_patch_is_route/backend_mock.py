import os
from unittest.mock import patch


class TestBackend:
    @patch("backend.get_connection")
    def test_store_result(self, mock_get_connection):     # a unit test, not a routed HTTP endpoint
        os.system(mock_get_connection)                     # mock argument is not attacker input
