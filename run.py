import json
import urllib.parse
import boto3
import time
import os
import logging
import base64
from datetime import datetime
from math import ceil
import sys

logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter(
    '%(asctime)s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def fetch_amis(ec2):
    # ec2
    response = ec2.describe_instances()
    reservations = response.get('Reservations')
    amis = []
    for reservation in reservations:
        for instance in reservation.get('Instances'):
            ami = instance.get('ImageId')
            if ami not in amis:
                amis.append(ami)
    return amis


def start_ec2_intances(instance_type, amis, user_data, tags,
                       subnet_id, instance_security_group):
    instances = []
    for ami in amis:
        instance = ec2.run_instances(ImageId=ami,
                                     InstanceType=instance_type,
                                     UserData=user_data,
                                     DryRun=False,
                                     MaxCount=1,
                                     MinCount=1,
                                     SecurityGroupIds=[
                                         instance_security_group],
                                     SubnetId=subnet_id,
                                     TagSpecifications=[
                                         {'ResourceType': 'instance', 'Tags': tags}]
                                     )
        instances.append(instance)
    instance_ids = [
        instance['InstanceId'] for instance_list in instances for instance in instance_list['Instances']]
    print(instance_ids)

    return instance_ids


def terminate_ec2_instances(ec2, instance_ids):
    ec2.terminate_instances(InstanceIds=instance_ids)


def start_inspector_scan(inspector, scan_template):
    response = inspector.start_assessment_run(
        assessmentTemplateArn=scan_template,
        assessmentRunName=f'running-amis-scheduled-scan-{datetime.today().date()}'
    )
    return response.get('assessmentRunArn')


def await_inspector_results(inspector, assessment_run_arn, day):
    assessment_completed = False
    max_total_wait = 7260
    total_wait = 0
    sleep_time = 60
    while not assessment_completed:
        response = inspector.describe_assessment_runs(
            assessmentRunArns=[assessment_run_arn])
        runs = filter(lambda x: day == x.get('createdAt').date(),
                      response.get('assessmentRuns'))
        if not runs:
            logger.fatal("No assessment runs found!")

        for run in runs:
            state = run.get('state')
            if state == 'COMPLETED' or state == 'COMPLETED_WITH_ERRORS':
                logger.info("Inspector scan completed")
                assessment_completed = True
                return assessment_completed

        logger.info(
            f"Inspector scan not completed yet. Waiting {sleep_time} seconds.")
        time.sleep(sleep_time)
        total_wait += sleep_time
        if total_wait >= max_total_wait:
            logger.error("Exceeded inspector max wait")
            return False
    return False


def retrieve_finding_arns(inspector, assessment_run_arn, finding_filter):
    finding_arns = []
    more_findings = True
    next_token = ""
    while more_findings:
        if next_token:
            response = inspector.list_findings(
                assessmentRunArns=[assessment_run_arn],
                maxResults=500,
                filter=finding_filter,
                nextToken=next_token
            )
        else:
            response = inspector.list_findings(
                assessmentRunArns=[assessment_run_arn],
                maxResults=500,
                filter=finding_filter,
            )
        next_token = response.get('nextToken')
        finding_arns = finding_arns + response.get('findingArns')
        if not next_token:
            more_findings = False
    return finding_arns


def retrieve_findings(inspector, finding_arns):
    amount_of_findings = len(finding_arns)
    findings = []
    for index in range(0, ceil(amount_of_findings / 100)):
        pagination_start = index*100
        pagination_end = pagination_start + 99
        if pagination_end > amount_of_findings:
            pagination_end = amount_of_findings - 1
        findings = findings + \
            inspector.describe_findings(
                findingArns=finding_arns[pagination_start:pagination_end]).get('findings')
    return findings


def publish_finding_data(sns, topic, message):
    sns.publish(
        TopicArn=topic,
        Message=message
    )


if __name__ == "__main__":

    sns_alert_topic = os.environ.get('SNS_ALERT_TOPIC_ARN')
    subnet_id = os.environ.get(
        'INSTANCE_SUBNET_ID')
    instance_security_group = os.environ.get(
        'INSTANCE_SECURITY_GROUP')
    assessment_template = os.environ.get(
        'INSPECTOR_ASSESSMENT_TEMPLATE')
    region = os.environ.get('AWS_DEFAULT_REGION', default='us-east-1')

    # Initialize clients
    ec2 = boto3.client('ec2', region)
    inspector = boto3.client('inspector', region)
    sns = boto3.client('sns', region)

    # Fetch AMIs
    logger.info("Fetching AMIs in use")
    amis = fetch_amis(ec2)
    if not amis:
        logger.fatal('No AMIs found')
        sys.exit(1)

    user_data = """#!/bin/bash -xe
sudo yum install -y awslogs
sudo systemctl start awslogsd
wget https://d1wk0tztpsntt1.cloudfront.net/linux/latest/inspector.gpg
gpg --import inspector.gpg
wget https://inspector-agent.amazonaws.com/linux/latest/install
curl -O https://d1wk0tztpsntt1.cloudfront.net/linux/latest/install.sig
gpg --verify ./install.sig
sudo bash install
sudo systemctl start awsagent
sudo systemctl status awsagent
"""
    instance_type = 't2.micro'
    tags = [{'Key': 'vulnerability-assessment', 'Value': 'true'}]

    # Run instances
    logger.info(f'Starting EC2 instances with AMIs: {amis}')
    instance_ids = start_ec2_intances(instance_type, amis, user_data, tags,
                                      subnet_id, instance_security_group)

    try:
        logger.info(f'Started instances {instance_ids}')
        ec2_waiter = ec2.get_waiter('instance_status_ok')

        logger.info(f'Awaiting {instance_ids}')
        ec2_waiter.wait(InstanceIds=instance_ids)

        logger.info('Starting Inspector run')
        assessment_run_arn = start_inspector_scan(
            inspector, assessment_template)

        logger.info('Awaiting Inspector results')
        await_inspector_results(
            inspector, assessment_run_arn, datetime.today().date())

        logger.info('Retrieving findings')
        # Only alert on high findings
        finding_filter = {'severities': ['High']}
        finding_arns = retrieve_finding_arns(
            inspector,
            assessment_run_arn,
            finding_filter
        )

        if finding_arns:
            amount_of_findings = len(finding_arns)

            logger.info('Publishing amount of high findings')
            message = f'Inspector scan resulted in {amount_of_findings} findings with filter {finding_filter}'
            publish_finding_data(sns, sns_alert_topic, message)
        else:
            logger.info(
                f'No findings found for assessment run {assessment_run_arn}')

    finally:
        # Always tear down VMs
        logger.info('Tearing down EC2 instances')
        terminate_ec2_instances(ec2, instance_ids)
