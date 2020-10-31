import pytest
from heimdall.models.role import Role
from unittest.mock import patch


class TestRoleModel:
    @pytest.fixture(scope='module')
    def new_role(self):
        return Role('admin', 'admin users can do everything')

    def test_create_new_role_sets_name_property(self, new_role):
        assert new_role.name == 'admin'

    def test_create_new_role_sets_description_property(self, new_role):
        assert new_role.description == 'admin users can do everything'

    def test_repr_returns_role_representation(self, new_role):
        assert new_role.__repr__() == '<Role admin>'
