"""add unified assessment fields to bank change requests

Revision ID: 0004_unified_assessment
Revises: 0003_bank_approvals
Create Date: 2026-11-20 04:06:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0004_unified_assessment'
down_revision: Union[str, None] = '0003_bank_approvals'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'bank_change_requests',
        sa.Column('linked_incident_ids', sa.JSON(), nullable=True, server_default='[]')
    )
    op.add_column(
        'bank_change_requests',
        sa.Column('risk_assessment_snapshot', sa.JSON(), nullable=True, server_default='{}')
    )


def downgrade() -> None:
    op.drop_column('bank_change_requests', 'risk_assessment_snapshot')
    op.drop_column('bank_change_requests', 'linked_incident_ids')
