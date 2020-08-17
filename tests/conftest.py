"""Setup the test fixtures used by pytest."""

import pytest

from heimdall import create_app


@pytest.fixture(scope='module')
def client():
    """Initialize the application for testing."""

    app = create_app('heimdall.config.TestConfig')
    test_client = app.test_client()

    # Establish an application context before running the tests
    context = app.app_context()
    context.push()

    # Run the tests with the application context
    yield test_client

    # Clean up the test environment
    context.pop()
