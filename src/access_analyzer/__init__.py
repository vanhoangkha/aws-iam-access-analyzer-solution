"""AWS IAM Access Analyzer SDK."""

from .client import AccessAnalyzerClient
from .cicd import PolicyValidator
from .dashboard import SecurityDashboard

__version__ = "1.0.0"
__all__ = ["AccessAnalyzerClient", "PolicyValidator", "SecurityDashboard"]
