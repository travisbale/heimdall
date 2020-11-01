import pytest
from heimdall.models.permission_assignment import PermissionAssignment


class TestPermissionAssignmentModel:
    @pytest.fixture(scope='module')
    def permission_assignment(self):
        return PermissionAssignment(1, 2)

    def test_create_permission_assignment_sets_role_id(self, permission_assignment):
        assert permission_assignment.role_id == 1

    def test_create_permission_assignment_sets_permission_id(self, permission_assignment):
        assert permission_assignment.permission_id == 2
