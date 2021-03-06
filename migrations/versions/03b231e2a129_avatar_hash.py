"""avatar_hash

Revision ID: 03b231e2a129
Revises: 0c6786e8c54f
Create Date: 2018-12-12 22:11:14.305487

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '03b231e2a129'
down_revision = '0c6786e8c54f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('avatar_hash', sa.String(length=32), nullable=True))
    op.create_index(op.f('ix_users_avatar_hash'), 'users', ['avatar_hash'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_users_avatar_hash'), table_name='users')
    op.drop_column('users', 'avatar_hash')
    # ### end Alembic commands ###
