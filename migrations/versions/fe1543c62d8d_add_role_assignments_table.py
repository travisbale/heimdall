"""Add role assignments table

Revision ID: fe1543c62d8d
Revises: 0d8d1d002e5f
Create Date: 2020-10-31 08:36:49.498680

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "fe1543c62d8d"
down_revision = "0d8d1d002e5f"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "role_assignments",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "role_id"),
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("role_assignments")
    # ### end Alembic commands ###
