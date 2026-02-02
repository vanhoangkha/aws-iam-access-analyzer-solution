from diagrams import Diagram, Cluster, Edge
from diagrams.aws.security import IAMAccessAnalyzer, IAM, KMS, SecretsManager
from diagrams.aws.integration import Eventbridge, SNS, SQS
from diagrams.aws.compute import Lambda
from diagrams.aws.management import Cloudwatch
from diagrams.aws.storage import S3
from diagrams.aws.devtools import Codepipeline, Codebuild
from diagrams.aws.general import User
from diagrams.aws.database import RDS, DynamodbTable

graph_attr = {
    "fontsize": "24",
    "bgcolor": "#f5f5f5",
    "pad": "0.5",
    "splines": "spline",
}

with Diagram(
    "IAM Access Analyzer Solution",
    filename="/home/ubuntu/aws-iam-access-analyzer-samples/architecture",
    show=False,
    direction="LR",
    graph_attr=graph_attr,
    outformat="png"
):
    
    # Users
    dev = User("Developer")
    security = User("Security\nTeam")
    
    # CI/CD
    with Cluster("CI/CD Pipeline", graph_attr={"bgcolor": "#e3f2fd"}):
        cicd = Codepipeline("CodePipeline")
        build = Codebuild("CodeBuild")
        validator = Lambda("Policy\nValidator")
    
    # Access Analyzer
    with Cluster("IAM Access Analyzer", graph_attr={"bgcolor": "#fff3e0"}):
        analyzer = IAMAccessAnalyzer("Analyzer")
    
    # Resources
    with Cluster("Monitored Resources (15 types)", graph_attr={"bgcolor": "#e8f5e9"}):
        s3 = S3("S3")
        iam = IAM("IAM")
        kms = KMS("KMS")
        lambda_fn = Lambda("Lambda")
        sqs = SQS("SQS")
        sns_r = SNS("SNS")
        secrets = SecretsManager("Secrets")
        rds = RDS("RDS")
        ddb = DynamodbTable("DynamoDB")
    
    # Alerting
    with Cluster("Real-time Alerting", graph_attr={"bgcolor": "#fce4ec"}):
        eb = Eventbridge("EventBridge")
        sns = SNS("SNS\nAlerts")
        logs = Cloudwatch("CloudWatch\nLogs")
    
    # Flows
    dev >> Edge(color="#1976d2", style="bold") >> cicd >> build >> validator
    validator >> Edge(label="validate", color="#ff9800", style="bold") >> analyzer
    
    analyzer >> Edge(style="dashed", color="#4caf50") >> [s3, iam, kms]
    analyzer >> Edge(style="dashed", color="#4caf50") >> [lambda_fn, sqs, sns_r]
    analyzer >> Edge(style="dashed", color="#4caf50") >> [secrets, rds, ddb]
    
    analyzer >> Edge(label="findings", color="#f44336", style="bold") >> eb
    eb >> sns >> security
    eb >> logs
