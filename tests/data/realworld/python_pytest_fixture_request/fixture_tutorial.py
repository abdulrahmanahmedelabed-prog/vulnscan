import importlib

import pytest


@pytest.fixture(name="client", params=["tutorial001"])
def get_client(request: pytest.FixtureRequest):
    # pytest's FixtureRequest: request.param comes from the params list above, not from an HTTP client
    return importlib.import_module(f"docs_src.body_updates.{request.param}")
