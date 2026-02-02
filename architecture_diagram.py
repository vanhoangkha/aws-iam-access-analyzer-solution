from diagrams import Diagram, Cluster, Edge
from diagrams.aws.security import IAMAccessAnalyzer, IAM
from diagrams.aws.integration import Eventbridge, SNS
from diagrams.aws.compute import Lambda
from diagrams.aws.management import Cloudwatch
from diagrams.aws.storage import S3
from diagrams.aws.devtools import Codepipeline
from diagrams.aws.general import User

with Diagram("IAM Access Analyzer Solution", filename="/home/ubuntu/aws-iam-access-analyzer-samples/architecture", show=False, direction="LR"):
    
    user = User("Security Team")
    
    with Cluster("CI/CD Pipeline"):
        pipeline = Codepipeline("CodePipeline")
        validation = Lambda("Policy\nValidation")
    
    with Cluster("IAM Access Analyzer"):
        analyzer = IAMAccessAnalyzer("Access\nAnalyzer")
        
    with Cluster("Monitored Resources"):
        s3 = S3("S3 Buckets")
        iam = IAM("IAM Roles")
    
    with Cluster("Alerting"):
        eventbridge = Eventbridge("EventBridge")
        sns = SNS("SNS")
        logs = Cloudwatch("CloudWatch\nLogs")
    
    # Flows
    pipeline >> validation >> analyzer
    analyzer >> Edge(label="findings") >> eventbridge
    eventbridge >> sns >> user
    eventbridge >> logs
    analyzer >> Edge(label="scan", style="dashed") >> [s3, iam]
