import pytest
from heimdall.models.permission import Permission
from unittest.mock import patch


class TestPermissionModel:
    @pytest.fixture(scope='module')
    def new_permission(self):
        return Permission('read:stuff', 'Users can read stuff')

    def test_create_new_permission_sets_name_property(self, new_permission):
        assert new_permission.name == 'read:stuff'

    def test_create_new_permission_sets_description_property(self, new_permission):
        assert new_permission.description == 'Users can read stuff'

    def test_repr_returns_permission_representation(self, new_permission):
        assert new_permission.__repr__() == '<Permission read:stuff>'
