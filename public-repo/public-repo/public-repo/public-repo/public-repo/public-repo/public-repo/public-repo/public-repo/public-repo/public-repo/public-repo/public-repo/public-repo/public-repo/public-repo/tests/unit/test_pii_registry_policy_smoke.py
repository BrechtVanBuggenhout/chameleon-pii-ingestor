from argparse import Namespace

from scripts.pii_registry_policy_smoke import format_issue, run_policy_smoke


class FakeVault:
    def __init__(self, base_url, tenant_id):
        self.base_url = base_url
        self.tenant_id = tenant_id
        self.shutdown_called = False

    def fetch_pii_registry_policy(self):
        return {
            "status": "WARN",
            "evaluations": [
                {
                    "resourceId": "bigquery:dataset.mart_customer_metrics",
                    "status": "WARN",
                    "issues": [
                        {
                            "severity": "WARNING",
                            "code": "MANUAL_REVIEW_REQUIRED",
                            "field": "user_surrogate_id",
                            "message": "Manual review is required.",
                        }
                    ],
                }
            ],
        }

    def shutdown(self):
        self.shutdown_called = True


def test_format_issue_expands_warning_details():
    issue = {
        "severity": "WARNING",
        "code": "MANUAL_REVIEW_REQUIRED",
        "field": "user_surrogate_id",
        "message": "Manual review is required.",
    }

    assert (
        format_issue(issue)
        == "  - WARNING MANUAL_REVIEW_REQUIRED field=user_surrogate_id: Manual review is required."
    )


def test_policy_smoke_prints_evaluations(capsys):
    args = Namespace(vault_url="http://mock-vault", tenant_id="tenant-a")

    policy = run_policy_smoke(args, vault_factory=FakeVault)

    output = capsys.readouterr().out
    assert policy["status"] == "WARN"
    assert "Policy status: WARN" in output
    assert "WARN bigquery:dataset.mart_customer_metrics" in output
    assert "MANUAL_REVIEW_REQUIRED" in output
