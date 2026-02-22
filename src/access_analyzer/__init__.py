"""AWS IAM Access Analyzer SDK - Production Ready."""

from .client import AccessAnalyzerClient
from .cicd import PolicyValidator
from .dashboard import SecurityDashboard

__version__ = "1.0.0"
__author__ = "Kha Van"
__email__ = "khavan.work@gmail.com"
__all__ = ["AccessAnalyzerClient", "PolicyValidator", "SecurityDashboard"]


def health_check() -> dict:
    """Verify AWS connectivity and permissions."""
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    
    result = {
        'status': 'healthy',
        'version': __version__,
        'checks': {}
    }
    
    # Check credentials
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        result['checks']['credentials'] = {
            'status': 'ok',
            'account': identity['Account'],
            'arn': identity['Arn']
        }
    except NoCredentialsError:
        result['status'] = 'unhealthy'
        result['checks']['credentials'] = {'status': 'error', 'message': 'No credentials found'}
        return result
    except ClientError as e:
        result['status'] = 'unhealthy'
        result['checks']['credentials'] = {'status': 'error', 'message': str(e)}
        return result
    
    # Check Access Analyzer permissions
    try:
        aa = boto3.client('accessanalyzer', region_name='us-east-1')
        aa.list_analyzers(maxResults=1)
        result['checks']['access_analyzer'] = {'status': 'ok'}
    except ClientError as e:
        result['checks']['access_analyzer'] = {
            'status': 'error',
            'message': e.response['Error']['Code']
        }
        if 'AccessDenied' in str(e):
            result['status'] = 'degraded'
    
    return result
