"""initial sentinel schema

Revision ID: 0001_initial
Revises: 
Create Date: 2026-11-20 02:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create service_identities table
    op.create_table(
        'service_identities',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('service_id', sa.String(length=100), nullable=False),
        sa.Column('service_name', sa.String(length=150), nullable=False),
        sa.Column('source_system', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='ACTIVE', nullable=False),
        sa.Column('allowed_ips', sa.String(length=500), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_service_identities_service_id'), 'service_identities', ['service_id'], unique=True)
    op.create_index(op.f('ix_service_identities_source_system'), 'service_identities', ['source_system'], unique=False)

    # 2. Create api_events table
    op.create_table(
        'api_events',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('event_id', sa.String(length=64), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('source_system', sa.String(length=50), nullable=False),
        sa.Column('service_identity', sa.String(length=100), nullable=False),
        sa.Column('endpoint', sa.String(length=255), nullable=False),
        sa.Column('http_method', sa.String(length=10), nullable=False),
        sa.Column('http_status_code', sa.Integer(), nullable=False),
        sa.Column('request_size_bytes', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('response_size_bytes', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('source_ip', sa.String(length=45), nullable=False),
        sa.Column('auth_identity', sa.String(length=100), nullable=False),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource_type', sa.String(length=100), nullable=False),
        sa.Column('resource_id', sa.String(length=255), nullable=True),
        sa.Column('approval_reference', sa.String(length=100), nullable=True),
        sa.Column('payload_hash', sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_api_events_event_id'), 'api_events', ['event_id'], unique=True)
    op.create_index(op.f('ix_api_events_timestamp'), 'api_events', ['timestamp'], unique=False)
    op.create_index(op.f('ix_api_events_received_at'), 'api_events', ['received_at'], unique=False)
    op.create_index(op.f('ix_api_events_source_system'), 'api_events', ['source_system'], unique=False)
    op.create_index(op.f('ix_api_events_service_identity'), 'api_events', ['service_identity'], unique=False)
    op.create_index(op.f('ix_api_events_endpoint'), 'api_events', ['endpoint'], unique=False)
    op.create_index(op.f('ix_api_events_http_method'), 'api_events', ['http_method'], unique=False)
    op.create_index(op.f('ix_api_events_http_status_code'), 'api_events', ['http_status_code'], unique=False)
    op.create_index(op.f('ix_api_events_source_ip'), 'api_events', ['source_ip'], unique=False)
    op.create_index(op.f('ix_api_events_auth_identity'), 'api_events', ['auth_identity'], unique=False)
    op.create_index(op.f('ix_api_events_action'), 'api_events', ['action'], unique=False)
    op.create_index(op.f('ix_api_events_resource_type'), 'api_events', ['resource_type'], unique=False)
    
    # Composite indexes for high performance security queries
    op.create_index('ix_api_events_ts_source', 'api_events', ['timestamp', 'source_system'], unique=False)
    op.create_index('ix_api_events_service_endpoint', 'api_events', ['service_identity', 'endpoint'], unique=False)
    op.create_index('ix_api_events_auth_action', 'api_events', ['auth_identity', 'action'], unique=False)

    # 3. Create security_audit_events table
    op.create_table(
        'security_audit_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('audit_id', sa.String(length=64), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('event_id_referenced', sa.String(length=64), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_security_audit_events_audit_id'), 'security_audit_events', ['audit_id'], unique=True)
    op.create_index(op.f('ix_security_audit_events_timestamp'), 'security_audit_events', ['timestamp'], unique=False)
    op.create_index(op.f('ix_security_audit_events_severity'), 'security_audit_events', ['severity'], unique=False)
    op.create_index(op.f('ix_security_audit_events_event_type'), 'security_audit_events', ['event_type'], unique=False)
    op.create_index(op.f('ix_security_audit_events_event_id_referenced'), 'security_audit_events', ['event_id_referenced'], unique=False)


def downgrade() -> None:
    op.drop_table('security_audit_events')
    op.drop_table('api_events')
    op.drop_table('service_identities')
