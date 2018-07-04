"""empty message

Revision ID: 609f33513ed6
Revises: 5de17511ee30
Create Date: 2018-06-29 12:45:57.934072

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '609f33513ed6'
down_revision = '5de17511ee30'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('pic', sa.Text(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'pic')
    # ### end Alembic commands ###
