from diagrams import Diagram, Cluster, Edge
from diagrams.aws.security import IAMAccessAnalyzer, IAM
from diagrams.aws.integration import Eventbridge, SNS
from diagrams.aws.compute import Lambda
from diagrams.aws.management import Cloudwatch
from diagrams.aws.devtools import Codepipeline
from diagrams.aws.general import User
from diagrams.aws.storage import S3

with Diagram("IAM Access Analyzer - High Level Architecture", filename="/home/ubuntu/aws-iam-access-analyzer-samples/architecture", show=False, direction="TB", graph_attr={"fontsize": "20", "bgcolor": "white"}):
    
    dev = User("Developer")
    security = User("Security Team")
    
    with Cluster("CI/CD Pipeline"):
        cicd = Codepipeline("CI/CD")
    
    with Cluster("IAM Access Analyzer"):
        analyzer = IAMAccessAnalyzer("Access Analyzer")
    
    with Cluster("AWS Resources"):
        resources = S3("S3, IAM, KMS\nLambda, SQS, SNS\nRDS, DynamoDB...")
    
    with Cluster("Alerting"):
        eb = Eventbridge("EventBridge")
        sns = SNS("SNS")
        logs = Cloudwatch("CloudWatch")
    
    # Flows
    dev >> Edge(label="deploy policy") >> cicd
    cicd >> Edge(label="validate") >> analyzer
    analyzer >> Edge(label="scan", style="dashed") >> resources
    analyzer >> Edge(label="findings") >> eb
    eb >> sns >> security
    eb >> logs
