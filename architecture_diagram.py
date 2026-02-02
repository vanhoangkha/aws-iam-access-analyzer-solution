from diagrams import Diagram, Cluster, Edge
from diagrams.aws.security import IAMAccessAnalyzer, IAM, KMS, SecretsManager
from diagrams.aws.integration import Eventbridge, SNS, SQS
from diagrams.aws.compute import Lambda
from diagrams.aws.management import Cloudwatch
from diagrams.aws.storage import S3, EBS
from diagrams.aws.devtools import Codepipeline, Codebuild
from diagrams.aws.general import User
from diagrams.aws.database import RDS, DynamodbTable

with Diagram("IAM Access Analyzer - Complete Architecture", filename="/home/ubuntu/aws-iam-access-analyzer-samples/architecture", show=False, direction="TB", graph_attr={"splines": "ortho", "nodesep": "0.8", "ranksep": "1.0"}):
    
    user = User("Security Team")
    
    with Cluster("CI/CD Pipeline"):
        pipeline = Codepipeline("CodePipeline")
        build = Codebuild("CodeBuild")
        validation = Lambda("Policy Validator")
    
    with Cluster("IAM Access Analyzer"):
        analyzer = IAMAccessAnalyzer("Access Analyzer")
    
    with Cluster("Supported Resources"):
        with Cluster("Storage"):
            s3 = S3("S3 Buckets")
            ebs = EBS("EBS Snapshots")
        with Cluster("Compute & Database"):
            lambda_fn = Lambda("Lambda")
            rds = RDS("RDS Snapshots")
            dynamodb = DynamodbTable("DynamoDB")
        with Cluster("Security"):
            iam = IAM("IAM Roles")
            kms = KMS("KMS Keys")
            secrets = SecretsManager("Secrets Manager")
        with Cluster("Messaging"):
            sqs = SQS("SQS Queues")
            sns_resource = SNS("SNS Topics")
    
    with Cluster("Alerting & Monitoring"):
        eventbridge = Eventbridge("EventBridge")
        sns = SNS("SNS Alerts")
        logs = Cloudwatch("CloudWatch Logs")
    
    # CI/CD Flow
    pipeline >> build >> validation >> analyzer
    
    # Analyzer scans resources
    analyzer >> Edge(style="dashed", color="blue") >> [s3, ebs]
    analyzer >> Edge(style="dashed", color="blue") >> [lambda_fn, rds, dynamodb]
    analyzer >> Edge(style="dashed", color="blue") >> [iam, kms, secrets]
    analyzer >> Edge(style="dashed", color="blue") >> [sqs, sns_resource]
    
    # Alerting flow
    analyzer >> Edge(label="findings", color="red") >> eventbridge
    eventbridge >> sns >> user
    eventbridge >> logs
