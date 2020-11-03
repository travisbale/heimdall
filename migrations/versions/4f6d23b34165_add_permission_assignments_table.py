"""Add permission assignments table

Revision ID: 4f6d23b34165
Revises: 4db56fb65145
Create Date: 2020-10-31 09:53:57.182736

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '4f6d23b34165'
down_revision = '4db56fb65145'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'permission_assignments',
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('permission_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['permission_id'], ['permissions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('role_id', 'permission_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('permission_assignments')
    # ### end Alembic commands ###
