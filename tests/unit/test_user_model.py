"""Unit tests for the User class."""

import pytest
from heimdall.models import User
from unittest.mock import patch


@pytest.fixture(scope='module')
def new_user():
    return User('travis.bale@gmail.com', 'password')


def test_create_new_user_sets_email_property(new_user):
    assert new_user.email == 'travis.bale@gmail.com'


def test_create_new_user_hashes_password(mocker):
    mocker.patch('heimdall.models.argon2.hash', return_value='hashed password')
    user = User('travis.bale@gmail.com', 'password')
    assert user.password == 'hashed password'


def test_create_new_user_sets_registered_on_property():
    with patch('heimdall.models.datetime') as mock_date:
        mock_date.now.return_value = 'right now'
        user = User('travis.bale@gmail.com', 'password')
        assert user.registered_on == 'right now'
