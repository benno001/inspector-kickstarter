data "aws_region" "current" {}

resource "aws_cloudwatch_event_target" "cloudwatch_event_inspector_target" {
  target_id = "inspector_assessment"
  rule      = aws_cloudwatch_event_rule.cloudwatch_event_inspector_assessment_kickstart.name
  arn       = aws_ecs_cluster.ecs_inspector_assessment_cluster.arn
  role_arn  = aws_iam_role.ecs_inspector_events.arn

  ecs_target {
    launch_type         = "FARGATE"
    task_count          = 1
    task_definition_arn = aws_ecs_task_definition.ecs_inspector_assessment_kickstarter.arn

    network_configuration {
      security_groups = [aws_security_group.inspector_assessment_group_allow_egress.id]
      subnets         = [aws_subnet.subnet_inspector_assessment_private.id]
    }
  }
}

resource "aws_sns_topic" "sns_topic_inspector_alerts" {
  name              = "inspector-alerts-topic"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_cloudwatch_event_rule" "cloudwatch_event_inspector_assessment_kickstart" {
  name        = "inspector-assessment-kickstart"
  description = "Kickstart an Amazon Inspector assessment"

  schedule_expression = "cron(0 3 * * ? *)"
}

resource "aws_ecs_cluster" "ecs_inspector_assessment_cluster" {
  name               = "inspector_assessment_cluster"
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]
}

resource "aws_ecs_task_definition" "ecs_inspector_assessment_kickstarter" {
  family                   = "inspector"
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  requires_compatibilities = ["FARGATE"]
  task_role_arn            = aws_iam_role.inspector_kickstarter_role.arn
  execution_role_arn       = aws_iam_role.inspector_kickstarter_role.arn

  container_definitions = <<DEFINITION
[
  {
    "cpu": 256,
    "environment": [
        {
            "name": "SNS_ALERT_TOPIC_ARN",
            "value": "${aws_sns_topic.sns_topic_inspector_alerts.arn}"
        },
        {
            "name": "INSTANCE_SUBNET_ID",
            "value": "${aws_subnet.subnet_inspector_assessment_private.id}"
        },
        {
            "name": "INSTANCE_SECURITY_GROUP",
            "value": "${aws_security_group.inspector_assessment_group_allow_egress.id}"
        },
        {
            "name": "INSPECTOR_ASSESSMENT_TEMPLATE",
            "value": "${aws_inspector_assessment_template.vulnerability_assessment_template.arn}"
        }
    ],
    "essential": true,
    "image": "docker.io/benno001/inspector-kickstarter:latest",
    "memory": 512,
    "memoryReservation": 64,
    "name": "inspector-kickstarter",
    "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
            "awslogs-create-group": "true",
            "awslogs-group": "/aws/ecs/inspector-kickstarter",
            "awslogs-region": "${data.aws_region.current.name}",
            "awslogs-stream-prefix": "ecs"
        }
    }
  }
]
DEFINITION
}

data "aws_inspector_rules_packages" "rules" {}

resource "aws_inspector_assessment_template" "vulnerability_assessment_template" {
  name       = "Full scan"
  target_arn = aws_inspector_assessment_target.vulnerability_assessment_targets.arn
  duration   = 3600

  rules_package_arns = data.aws_inspector_rules_packages.rules.arns
}

resource "aws_inspector_resource_group" "vulnerability_assessment_instance_attributes" {
  tags = {
    vulnerability-assessment = "true"
  }
}

resource "aws_inspector_assessment_target" "vulnerability_assessment_targets" {
  name               = "assessment target"
  resource_group_arn = aws_inspector_resource_group.vulnerability_assessment_instance_attributes.arn
}

# Add security group that does not allow inbound traffic
resource "aws_security_group" "inspector_assessment_group_allow_egress" {
  name        = "inspector_assessment_group_allow_egress"
  description = "Allow outbound traffic"
  vpc_id      = aws_vpc.vpc_inspector_assessments.id

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    vulnerability-assessment = "true"
  }
}



resource "aws_iam_policy" "inspector_kickstarter_policy" {
  name        = "inspector_kickstarter_policy"
  path        = "/"
  description = "Policy for handling automatic AWS inspector assessments"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLogging",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
      ],
      "Resource": ["arn:aws:logs:*:*:*"]
    },
    {
      "Sid": "AllowCreateTagsInstances",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateTags"
      ],
      "Resource": ["arn:aws:ec2:*:*:instance/*"]
    },
    {
      "Sid": "AllowToDescribeAll",
      "Effect": "Allow",
      "Action": ["ec2:Describe*"],
      "Resource": "*"
    },
    {
      "Sid": "AllowRunInstances",
      "Effect": "Allow",
      "Action": ["ec2:RunInstances", "ec2:TerminateInstances"],
      "Resource": ["*"]
    },
    {
      "Sid": "AllowInspectorScanning",
      "Action": [
        "inspector:DescribeAssessmentRuns",
        "inspector:DescribeAssessmentTemplates",
        "inspector:DescribeFindings",
        "inspector:ListAssessmentRuns",
        "inspector:ListAssessmentTemplates",
        "inspector:ListFindings",
        "inspector:StartAssessmentRun"
      ],
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Sid": "AllowSNSTopicPublishing",
      "Action": ["sns:Publish"],
      "Effect": "Allow",
      "Resource": "${aws_sns_topic.sns_topic_inspector_alerts.arn}"
    }
  ]
}
EOF
}

resource "aws_iam_role" "inspector_kickstarter_role" {
  name = "inspector_kickstarter_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": [
          "ec2.amazonaws.com",
          "ecs-tasks.amazonaws.com"
        ]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "inspector_role_policy_attachment" {
  role       = aws_iam_role.inspector_kickstarter_role.name
  policy_arn = aws_iam_policy.inspector_kickstarter_policy.arn
}

resource "aws_iam_role" "ecs_inspector_events" {
  name = "ecs_inspector_events"

  assume_role_policy = <<DOC
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
DOC
}

resource "aws_iam_role_policy" "ecs_events_inspector_run_task" {
  name = "ecs_events_inspector_run_task"
  role = aws_iam_role.ecs_inspector_events.id

  policy = <<DOC
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
              "ecs:RunTask",
              "ecs:StartTask"
            ],
            "Resource": "${aws_ecs_task_definition.ecs_inspector_assessment_kickstarter.arn}"
        },
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": [
                "${aws_iam_role.inspector_kickstarter_role.arn}"
            ],
            "Condition": {
                "StringLike": {
                    "iam:PassedToService": "ecs-tasks.amazonaws.com"
                }
            }
        }
    ]
}
DOC
}

# Create a vpc with internet gateway, NAT gateway and public/private subnet
resource "aws_vpc" "vpc_inspector_assessments" {
  cidr_block                       = var.vpc_inspector_assessment_cidr
  assign_generated_ipv6_cidr_block = true
  tags = {
    vulnerability-assessment = "true"
  }
}

resource "aws_internet_gateway" "internet_gateway_inspector_assessments" {
  vpc_id = aws_vpc.vpc_inspector_assessments.id
}

resource "aws_eip" "eip_nat_gateway_inspector" {}

resource "aws_nat_gateway" "nat_gateway_inspector" {
  allocation_id = aws_eip.eip_nat_gateway_inspector.id
  subnet_id     = aws_subnet.subnet_inspector_assessment_public.id
}


resource "aws_subnet" "subnet_inspector_assessment_public" {
  vpc_id     = aws_vpc.vpc_inspector_assessments.id
  cidr_block = cidrsubnet(var.vpc_inspector_assessment_cidr, 8, 0)
}

resource "aws_subnet" "subnet_inspector_assessment_private" {
  vpc_id     = aws_vpc.vpc_inspector_assessments.id
  cidr_block = cidrsubnet(var.vpc_inspector_assessment_cidr, 8, 1)
  tags = {
    vulnerability-assessment = "true"
  }
}

resource "aws_main_route_table_association" "main_route_table_association_inspector_vpc" {
  vpc_id         = aws_vpc.vpc_inspector_assessments.id
  route_table_id = aws_route_table.main_route_table_inspector.id
}

resource "aws_route_table_association" "custom_route_table_association_inspector_vpc" {
  subnet_id      = aws_subnet.subnet_inspector_assessment_public.id
  route_table_id = aws_route_table.custom_route_table_inspector.id
}

resource "aws_route_table" "main_route_table_inspector" {
  vpc_id = aws_vpc.vpc_inspector_assessments.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gateway_inspector.id
  }
}

resource "aws_route_table" "custom_route_table_inspector" {
  vpc_id = aws_vpc.vpc_inspector_assessments.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.internet_gateway_inspector_assessments.id
  }
}
