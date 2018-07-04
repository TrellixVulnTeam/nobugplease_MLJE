"""empty message

Revision ID: 6420a234034d
Revises: a88dd47d1223
Create Date: 2018-07-03 14:51:56.366304

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6420a234034d'
down_revision = 'a88dd47d1223'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('home', sa.Column('vie_description', sa.String(length=1024), nullable=True))
    op.add_column('posts', sa.Column('vie_content', sa.Text(), nullable=True))
    op.add_column('posts', sa.Column('vie_name', sa.String(length=128), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('posts', 'vie_name')
    op.drop_column('posts', 'vie_content')
    op.drop_column('home', 'vie_description')
    # ### end Alembic commands ###
