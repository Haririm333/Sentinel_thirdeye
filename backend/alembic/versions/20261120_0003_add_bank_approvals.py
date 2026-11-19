"""add two-person bank change approval tables

Revision ID: 0003_bank_approvals
Revises: 0002_incidents_rules
Create Date: 2026-11-20 03:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0003_bank_approvals'
down_revision: Union[str, None] = '0002_incidents_rules'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Vendor Bank Accounts
    op.create_table(
        'vendor_bank_accounts',
        sa.Column('vendor_id', sa.String(length=64), primary_key=True, nullable=False),
        sa.Column('vendor_name', sa.String(length=128), nullable=False),
        sa.Column('active_bank_account_ref', sa.String(length=64), nullable=False),
        sa.Column('encrypted_bank_details', sa.Text(), nullable=False),
        sa.Column('bank_name', sa.String(length=128), nullable=False),
        sa.Column('routing_number_masked', sa.String(length=64), nullable=False),
        sa.Column('version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index(op.f('ix_vendor_bank_accounts_vendor_id'), 'vendor_bank_accounts', ['vendor_id'], unique=True)

    # 2. Bank Change Requests
    op.create_table(
        'bank_change_requests',
        sa.Column('request_id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('vendor_id', sa.String(length=64), sa.ForeignKey('vendor_bank_accounts.vendor_id'), nullable=False),
        sa.Column('requester_id', sa.String(length=64), nullable=False),
        sa.Column('old_bank_account_ref', sa.String(length=64), nullable=False),
        sa.Column('proposed_bank_account_ref', sa.String(length=64), nullable=False),
        sa.Column('proposed_bank_name', sa.String(length=128), nullable=False),
        sa.Column('proposed_routing_masked', sa.String(length=64), nullable=False),
        sa.Column('encrypted_proposed_bank_details', sa.Text(), nullable=False),
        sa.Column('request_reason', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), server_default='PENDING_APPROVAL', nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('rejection_reason', sa.Text(), nullable=True),
        sa.Column('cancelled_by', sa.String(length=64), nullable=True)
    )
    op.create_index(op.f('ix_bank_change_requests_vendor_id'), 'bank_change_requests', ['vendor_id'])
    op.create_index(op.f('ix_bank_change_requests_requester_id'), 'bank_change_requests', ['requester_id'])
    op.create_index(op.f('ix_bank_change_requests_status'), 'bank_change_requests', ['status'])
    op.create_index(op.f('ix_bank_change_requests_fingerprint'), 'bank_change_requests', ['fingerprint'])
    op.create_index('ix_bank_req_vendor_status', 'bank_change_requests', ['vendor_id', 'status'])
    op.create_index('ix_bank_req_fingerprint_status', 'bank_change_requests', ['fingerprint', 'status'])

    # 3. Bank Approvals
    op.create_table(
        'bank_change_approvals',
        sa.Column('approval_id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('request_id', sa.String(length=36), sa.ForeignKey('bank_change_requests.request_id', ondelete='CASCADE'), nullable=False),
        sa.Column('approver_id', sa.String(length=64), nullable=False),
        sa.Column('decision', sa.String(length=16), server_default='APPROVE', nullable=False),
        sa.Column('approval_order', sa.Integer(), nullable=False),
        sa.Column('fingerprint_approved', sa.String(length=64), nullable=False),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('auth_context', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('request_id', 'approver_id', name='uq_bank_request_approver')
    )
    op.create_index(op.f('ix_bank_change_approvals_request_id'), 'bank_change_approvals', ['request_id'])
    op.create_index(op.f('ix_bank_change_approvals_approver_id'), 'bank_change_approvals', ['approver_id'])
    op.create_index('ix_bank_approval_req_order', 'bank_change_approvals', ['request_id', 'approval_order'])

    # 4. Bank Approval Audit Logs
    op.create_table(
        'bank_approval_audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, primary_key=True, nullable=False),
        sa.Column('request_id', sa.String(length=36), sa.ForeignKey('bank_change_requests.request_id', ondelete='CASCADE'), nullable=False),
        sa.Column('actor_id', sa.String(length=64), nullable=False),
        sa.Column('action', sa.String(length=32), nullable=False),
        sa.Column('result', sa.String(length=16), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index(op.f('ix_bank_approval_audit_logs_request_id'), 'bank_approval_audit_logs', ['request_id'])
    op.create_index(op.f('ix_bank_approval_audit_logs_actor_id'), 'bank_approval_audit_logs', ['actor_id'])
    op.create_index(op.f('ix_bank_approval_audit_logs_action'), 'bank_approval_audit_logs', ['action'])


def downgrade() -> None:
    op.drop_table('bank_approval_audit_logs')
    op.drop_table('bank_change_approvals')
    op.drop_table('bank_change_requests')
    op.drop_table('vendor_bank_accounts')
