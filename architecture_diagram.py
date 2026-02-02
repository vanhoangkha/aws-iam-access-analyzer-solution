from diagrams import Diagram, Cluster, Edge
from diagrams.aws.security import IAMAccessAnalyzer, IAM, KMS, SecretsManager
from diagrams.aws.integration import Eventbridge, SNS, SQS
from diagrams.aws.compute import Lambda
from diagrams.aws.management import Cloudwatch, CloudwatchEventTimeBased
from diagrams.aws.storage import S3, EBS
from diagrams.aws.devtools import Codepipeline, Codebuild
from diagrams.aws.general import User, Users
from diagrams.aws.database import RDS, DynamodbTable
from diagrams.aws.network import CloudFront

graph_attr = {
    "fontsize": "28",
    "fontname": "Helvetica Bold",
    "bgcolor": "white",
    "pad": "0.8",
    "splines": "spline",
    "nodesep": "1.0",
    "ranksep": "1.2",
}

node_attr = {
    "fontsize": "14",
    "fontname": "Helvetica",
}

edge_attr = {
    "fontsize": "12",
    "fontname": "Helvetica",
}

with Diagram(
    "AWS IAM Access Analyzer Solution",
    filename="/home/ubuntu/aws-iam-access-analyzer-samples/architecture",
    show=False,
    direction="LR",
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
    outformat="png"
):
    
    # Users
    dev = User("Developer")
    security = Users("Security Team")
    
    # CI/CD Pipeline
    with Cluster("CI/CD Pipeline", graph_attr={"bgcolor": "#E3F2FD", "fontsize": "16"}):
        pipeline = Codepipeline("CodePipeline")
        build = Codebuild("CodeBuild")
        validator = Lambda("Policy\nValidator")
        pipeline >> build >> validator
    
    # Access Analyzer Core
    with Cluster("IAM Access Analyzer", graph_attr={"bgcolor": "#FFF8E1", "fontsize": "16"}):
        analyzer = IAMAccessAnalyzer("Access\nAnalyzer")
    
    # Monitored Resources
    with Cluster("Monitored AWS Resources", graph_attr={"bgcolor": "#E8F5E9", "fontsize": "16"}):
        with Cluster("Storage & Compute"):
            s3 = S3("S3 Buckets")
            lambda_fn = Lambda("Lambda")
            ebs = EBS("EBS")
        
        with Cluster("Security"):
            iam = IAM("IAM Roles")
            kms = KMS("KMS Keys")
            secrets = SecretsManager("Secrets")
        
        with Cluster("Database & Messaging"):
            rds = RDS("RDS")
            ddb = DynamodbTable("DynamoDB")
            sqs = SQS("SQS")
            sns_r = SNS("SNS")
    
    # Alerting & Monitoring
    with Cluster("Alerting & Monitoring", graph_attr={"bgcolor": "#FCE4EC", "fontsize": "16"}):
        eventbridge = Eventbridge("EventBridge\nRules")
        sns_alert = SNS("SNS\nNotifications")
        logs = Cloudwatch("CloudWatch\nLogs")
    
    # Main Flow
    dev >> Edge(color="#1565C0", style="bold", penwidth="2.0") >> pipeline
    
    validator >> Edge(label="validate", color="#FF8F00", style="bold", penwidth="2.0") >> analyzer
    
    # Analyzer scanning resources
    analyzer >> Edge(style="dashed", color="#43A047", penwidth="1.5") >> s3
    analyzer >> Edge(style="dashed", color="#43A047", penwidth="1.5") >> iam
    analyzer >> Edge(style="dashed", color="#43A047", penwidth="1.5") >> kms
    analyzer >> Edge(style="dashed", color="#43A047", penwidth="1.5") >> lambda_fn
    analyzer >> Edge(style="dashed", color="#43A047", penwidth="1.5") >> ddb
    
    # Findings flow
    analyzer >> Edge(label="findings", color="#E53935", style="bold", penwidth="2.0") >> eventbridge
    eventbridge >> Edge(color="#E53935", penwidth="1.5") >> sns_alert
    eventbridge >> Edge(color="#7B1FA2", penwidth="1.5") >> logs
    sns_alert >> Edge(color="#E53935", style="bold", penwidth="2.0") >> security
