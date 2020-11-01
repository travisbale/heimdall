import pytest
from heimdall.models.role_assignment import RoleAssignment


class TestRoleAssignmentModel:
    @pytest.fixture(scope='module')
    def role_assignment(self):
        return RoleAssignment(1, 2)

    def test_create_role_assignment_sets_user_id(self, role_assignment):
        assert role_assignment.user_id == 1

    def test_create_role_assignment_sets_role_id(self, role_assignment):
        assert role_assignment.role_id == 2
