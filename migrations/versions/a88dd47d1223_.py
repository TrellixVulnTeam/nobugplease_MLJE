"""empty message

Revision ID: a88dd47d1223
Revises: f11c96fd4a33
Create Date: 2018-07-01 12:22:22.085561

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a88dd47d1223'
down_revision = 'f11c96fd4a33'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('posts', sa.Column('approved', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('posts', 'approved')
    # ### end Alembic commands ###