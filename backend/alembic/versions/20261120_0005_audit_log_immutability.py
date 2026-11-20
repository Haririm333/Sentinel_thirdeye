"""add database trigger for bank approval audit log immutability

Revision ID: 0005_audit_immutability
Revises: 0004_unified_assessment
Create Date: 2026-11-20 04:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0005_audit_immutability'
down_revision: Union[str, None] = '0004_unified_assessment'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Trigger function to prohibit any UPDATE or DELETE operations on bank_approval_audit_logs
    op.execute("""
    CREATE OR REPLACE FUNCTION block_audit_log_mutation()
    RETURNS TRIGGER AS $$
    BEGIN
        RAISE EXCEPTION 'bank_approval_audit_logs records are append-only and immutable; UPDATE and DELETE operations are strictly prohibited.';
    END;
    $$ LANGUAGE plpgsql;
    """)
    op.execute("""
    DROP TRIGGER IF EXISTS trg_bank_approval_audit_logs_immutable ON bank_approval_audit_logs;
    CREATE TRIGGER trg_bank_approval_audit_logs_immutable
    BEFORE UPDATE OR DELETE ON bank_approval_audit_logs
    FOR EACH ROW EXECUTE FUNCTION block_audit_log_mutation();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_bank_approval_audit_logs_immutable ON bank_approval_audit_logs;")
    op.execute("DROP FUNCTION IF EXISTS block_audit_log_mutation();")
