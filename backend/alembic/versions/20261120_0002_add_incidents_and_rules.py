"""add incidents and detection_rules tables

Revision ID: 0002_incidents_rules
Revises: 0001_initial
Create Date: 2026-11-20 02:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0002_incidents_rules'
down_revision: Union[str, None] = '0001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create detection_rules table
    op.create_table(
        'detection_rules',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('rule_id', sa.String(length=50), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('base_risk_score', sa.Integer(), nullable=False),
        sa.Column('is_enabled', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('parameters', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_detection_rules_rule_id'), 'detection_rules', ['rule_id'], unique=True)

    # 2. Create incidents table
    op.create_table(
        'incidents',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('incident_id', sa.String(length=64), nullable=False),
        sa.Column('rule_id', sa.String(length=50), nullable=False),
        sa.Column('rule_name', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='OPEN', nullable=False),
        sa.Column('service_identity', sa.String(length=100), nullable=False),
        sa.Column('related_event_ids', sa.JSON(), nullable=False),
        sa.Column('resource_type', sa.String(length=100), nullable=True),
        sa.Column('resource_id', sa.String(length=255), nullable=True),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_incidents_incident_id'), 'incidents', ['incident_id'], unique=True)
    op.create_index(op.f('ix_incidents_rule_id'), 'incidents', ['rule_id'], unique=False)
    op.create_index(op.f('ix_incidents_severity'), 'incidents', ['severity'], unique=False)
    op.create_index(op.f('ix_incidents_risk_score'), 'incidents', ['risk_score'], unique=False)
    op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)
    op.create_index(op.f('ix_incidents_service_identity'), 'incidents', ['service_identity'], unique=False)
    op.create_index(op.f('ix_incidents_created_at'), 'incidents', ['created_at'], unique=False)
    op.create_index(op.f('ix_incidents_updated_at'), 'incidents', ['updated_at'], unique=False)
    
    # Composite indexes for correlation & reporting
    op.create_index('ix_incidents_rule_service_status', 'incidents', ['rule_id', 'service_identity', 'status'], unique=False)
    op.create_index('ix_incidents_created_severity', 'incidents', ['created_at', 'severity'], unique=False)


def downgrade() -> None:
    op.drop_table('incidents')
    op.drop_table('detection_rules')
