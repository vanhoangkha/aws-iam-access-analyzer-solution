import * as iam from '@aws-cdk/aws-iam';
import * as cdk from '@aws-cdk/core';
import * as sqs from '@aws-cdk/aws-sqs';
import { AccountPrincipal, AccountRootPrincipal, CompositePrincipal } from '@aws-cdk/aws-iam';

export class DemoStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const myQueue = new sqs.Queue(this, 'MyQueue');
    
    myQueue.addToResourcePolicy(
      new iam.PolicyStatement({
        principals: [new AccountPrincipal("111122223333")],
        effect: iam.Effect.ALLOW,
        actions: ['sqs:SendMessage', 'sqs:ReceiveMessage'],
        resources: [myQueue.queueArn]
      }),
    )

    const role = new iam.Role(this, 'MyRole', {
      assumedBy: new CompositePrincipal(
        new AccountPrincipal("111222333444"),
        new AccountRootPrincipal()
      ) 
    });

    role.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['s3:ListBucket'],
      resources: ['arn:aws:s3:::bucket-name']
    }));
  }
}
