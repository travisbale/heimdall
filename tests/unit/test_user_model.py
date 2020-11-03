"""Unit tests for the User class."""

from unittest.mock import patch

import pytest

from heimdall.models.user import User


class TestUserModel:
    @pytest.fixture(scope='module')
    def new_user(self):
        return User('travis.bale@gmail.com', 'password')

    def test_create_new_user_sets_email_property(self, new_user):
        assert new_user.email == 'travis.bale@gmail.com'

    def test_create_new_user_hashes_password(self, mocker):
        mocker.patch('heimdall.models.user.argon2.hash', return_value='hashed password')
        user = User('travis.bale@gmail.com', 'password')
        assert user.password == 'hashed password'

    def test_create_new_user_sets_registered_on_property(self):
        with patch('heimdall.models.user.datetime') as mock_date:
            mock_date.now.return_value = 'right now'
            user = User('travis.bale@gmail.com', 'password')
            assert user.registered_on == 'right now'

    def test_setting_user_password_hashes_the_password(self, new_user, mocker):
        mocker.patch('heimdall.models.user.argon2.hash', return_value='hashed password')
        new_user.password = 'password'
        assert new_user.password == 'hashed password'

    def test_authenticate_user_returns_true_if_password_is_correct(self, new_user, mocker):
        mocker.patch('heimdall.models.user.argon2.verify', return_value='true')
        assert new_user.authenticate('password')

    def test_authenticate_user_returns_true_if_password_is_incorrect(self, new_user, mocker):
        mocker.patch('heimdall.models.user.argon2.verify', return_value='false')
        assert new_user.authenticate('password')

    def test_authenticate_user_returns_false_if_verify_throws_type_error(self, new_user, mocker):
        mocker.patch('heimdall.models.user.argon2.verify', side_effect=TypeError())
        assert not new_user.authenticate('password')

    def test_authenticate_user_returns_false_if_verify_throws_value_error(self, new_user, mocker):
        mocker.patch('heimdall.models.user.argon2.verify', side_effect=ValueError())
        assert not new_user.authenticate('password')
