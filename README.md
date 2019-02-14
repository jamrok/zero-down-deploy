# zero-down-deploy

  Deploy new EC2 instances based on a new AMI and replace old instances that were built with an old AMI into your environment, doing health checks and updating the load balancer accordingly. Newly created instances will have the same availability zones and number of instances per AZ as old instances (i.e. 1 to 1 replacement of old and new instances).

## Script Outline
  - Log script output to file (deploy.log) and screen
  - Parse arguments
  - Get AWS Credentials
  - Start Deployment
    - Verify AMI IDs
    - Get info about instances that use the AMIs
    - Find a load that contains the old AMI IDs
    - If they match up, create corresponding instances using new AMI ID
      - New instances will:
          - Have the same instance type, ssh key & security group as old instances
          - Have the same availability zones and number of instances per AZ as old
    - Update the load balancer
      - Ensure a health check exists on the LB (new instances won't go live until healthy)
      - Register new instances in LB
      - Wait for new instances to pass health checks
      - Ensure Connection Draining enabled
      - Deregister new instances if they fail health checks
      - Deregister old instances only if new instances pass health checks
    - Unless overridden, terminate new instances if new instances failed checks
    - Unless overridden, terminate old instances if new instances passed checks

## Contributors
  - Author: Jamrok

## Supporting Docs
  - [Boto 3 - ELB API Docs]( https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elb.html )
  - [Boto 3 - EC2 API Docs]( https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html )

## Assumptions
  - You have an AWS Account 🙂
  - You are using a Classic Elastic Load Balancer (script not yet updated to work with ELBv2).
  - You have valid old and new AMI IDs.
  - You have instances built with old AMIs in a load balancer.
  - The new AMI instances are web servers and will respond successfully to the health check defined in the load balancer. If no health check is defined, a generic HTTP port 80 check on / will be created.
  - Only one load balancer will be updated at this time.

## Precautions
  - There is no dry-run option 😅

## Rollback
  - If a failure occurs, it will attempt to roll back changes, such as deregistering newly added instances from the LB (always) and deleting newly created instances (default, but can be overridden)
  - If you find something that wasn't handled, it will need to be rolled back manually.

## Prerequisites
  - boto3 SDK
  - python >= 3
  - pip3
  - python3-virtualenv
  - git (optional)

## Compatibility
  - python >= 3.6.7 - Verified

## Syntax
```
usage: deploy.py [-h] [--keep] old_ami_id new_ami_id

[Description - same as above]

positional arguments:
  old_ami_id  The old AMI ID that is used by instances
  new_ami_id  The new AMI ID that you want to deploy

optional arguments:
  -h, --help  show this help message and exit
  --keep, -k  Don't terminate instances on failure (useful for investigations)
```

## Installation

#### Setup virtual environment
```
virtualenv zero_down_env --python=python3
source zero_down_env/bin/activate
```
#### Install the boto3 Python SDK
```
pip install boto3
```
#### Get the script via git or directly
```
git clone https://github.com/jamrok/zero-down-deploy.git
cd zero-down-deploy
```
or
```
wget https://raw.githubusercontent.com/jamrok/zero-down-deploy/master/deploy.py
chmod +x deploy.py
```

#### Ensure valid AWS credentials exist in either `~/.aws/credentials` or `~/.aws/config`
Sample file contents:
```
[default]
region = us-east-1
aws_access_key_id = BLAHBLAHBLAHBLAHBLAH
aws_secret_access_key = xyz123gibberishxyz123gibberishxyz1234+56
```

## Examples

#### Replace old AMI instances with new AMI instances

```bash
[user@linux]$ ./deploy.py ami-02df169db9a6c0ea6 ami-02981ab92476c1e41
<TIMESTAMP> INFO
Logging to file: deploy.log

<TIMESTAMP> INFO
Starting Deployment Process
Old AMI ID: ami-02df169db9a6c0ea6
New AMI ID: ami-02981ab92476c1e41

<TIMESTAMP> INFO
Found credentials in shared credentials file: ~/.aws/credentials

<TIMESTAMP> INFO
Verifying that the given AMIs exist

<TIMESTAMP> INFO
Locate the instances with the old and new image IDs.

<TIMESTAMP> INFO
Updated Old Instance Metadata: {'ami': 'ami-02df169db9a6c0ea6', 'az': {'us-east-1d': [{'id': 'i-0c8e8493acb85adbe', 'type': 't2.micro', 'keyname': 'id_rsa', 'security_group_ids': ['sg-0eb0b2d505594e52d']}], 'us-east-1b': [{'id': 'i-065b5b70da1163d01', 'type': 't2.micro', 'keyname': 'id_rsa', 'security_group_ids': ['sg-0eb0b2d505594e52d']}], 'us-east-1c': [{'id': 'i-04ca34b6f27e0adf9', 'type': 't2.micro', 'keyname': 'id_rsa', 'security_group_ids': ['sg-0eb0b2d505594e52d']}]}, 'ids': ['i-0c8e8493acb85adbe', 'i-065b5b70da1163d01', 'i-04ca34b6f27e0adf9']}

<TIMESTAMP> INFO
Find the load balancer that contains old AMI instances

<TIMESTAMP> INFO
Found LB: new-web-elb

<TIMESTAMP> INFO
Launching Instance: {'ami': 'ami-02981ab92476c1e41', 'az': {'us-east-1d': [{'id': 'i-043642e1d53b6ce4b', 'type': 't2.micro', 'keyname': 'id_rsa', 'security_group_ids': ['sg-0eb0b2d505594e52d']}]}, 'ids': ['i-043642e1d53b6ce4b']}

<TIMESTAMP> INFO
Launching Instance: {'ami': 'ami-02981ab92476c1e41', 'az': {'us-east-1b': [{'id': 'i-0b479e70c21c7d650', 'type': 't2.micro', 'keyname': 'id_rsa', 'security_group_ids': ['sg-0eb0b2d505594e52d']}]}, 'ids': ['i-0b479e70c21c7d650']}

<TIMESTAMP> INFO
Launching Instance: {'ami': 'ami-02981ab92476c1e41', 'az': {'us-east-1c': [{'id': 'i-013c97a8cbc5bd512', 'type': 't2.micro', 'keyname': 'id_rsa', 'security_group_ids': ['sg-0eb0b2d505594e52d']}]}, 'ids': ['i-013c97a8cbc5bd512']}

<TIMESTAMP> INFO
Instances were created. Waiting up to 600 seconds for them to come online

<TIMESTAMP> INFO
Instances online

<TIMESTAMP> INFO
Attempting to swap old and new instances in LB

<TIMESTAMP> INFO
Ensure that LB health check exists and add one if not

<TIMESTAMP> INFO
Added instances to LB: {'LoadBalancerName': 'new-web-elb', 'Instances': [{'InstanceId': 'i-043642e1d53b6ce4b'}, {'InstanceId': 'i-0b479e70c21c7d650'}, {'InstanceId': 'i-013c97a8cbc5bd512'}]}

<TIMESTAMP> INFO
Waiting up to 120 seconds for new instances in LB to be healthy

<TIMESTAMP> INFO
Ensuring Connection Draining is turned on

<TIMESTAMP> INFO
Deregistering instances from LB: {'LoadBalancerName': 'new-web-elb', 'Instances': [{'InstanceId': 'i-0c8e8493acb85adbe'}, {'InstanceId': 'i-065b5b70da1163d01'}, {'InstanceId': 'i-04ca34b6f27e0adf9'}]}

<TIMESTAMP> INFO
Waiting up to 120 seconds for instances in LB to be deregistered

<TIMESTAMP> INFO
Terminate the specified instance IDs & verify they no longer exist.

<TIMESTAMP> INFO
Successfully sent request to terminate instance:
[{'CurrentState': {'Code': 32, 'Name': 'shutting-down'}, 'InstanceId': 'i-0c8e8493acb85adbe', 'PreviousState': {'Code': 16, 'Name': 'running'}}]

<TIMESTAMP> INFO
Successfully sent request to terminate instance:
[{'CurrentState': {'Code': 32, 'Name': 'shutting-down'}, 'InstanceId': 'i-065b5b70da1163d01', 'PreviousState': {'Code': 16, 'Name': 'running'}}]

<TIMESTAMP> INFO
Successfully sent request to terminate instance:
[{'CurrentState': {'Code': 32, 'Name': 'shutting-down'}, 'InstanceId': 'i-04ca34b6f27e0adf9', 'PreviousState': {'Code': 16, 'Name': 'running'}}]

<TIMESTAMP> INFO
Waiting up to 600 seconds for instances to be terminated

<TIMESTAMP> INFO
Instances terminated successfully

<TIMESTAMP> INFO
Success: Deployment Completed
```
---

#### Attempt to introduce a new AMI that has bugs (failed health checks).
> **Note:**
> - The script automatically rolled back changes without the users being affected.
> - The script enabled Connection Draining because it was turned off

```bash
[user@linux]$ ./deploy.py ami-02981ab92476c1e41 ami-001e1c1159ccfe992
<TIMESTAMP> INFO
Logging to file: deploy.log

<TIMESTAMP> INFO
Starting Deployment Process
Old AMI ID: ami-02981ab92476c1e41
New AMI ID: ami-001e1c1159ccfe992

<TIMESTAMP> INFO
Found credentials in shared credentials file: ~/.aws/credentials

<TIMESTAMP> INFO
Verifying that the given AMIs exist

<TIMESTAMP> INFO
Locate the instances with the old and new image IDs.

<TIMESTAMP> INFO
Updated Old Instance Metadata: {'ami': 'ami-02981ab92476c1e41', 'az': {'us-east-1d': [{'id': 'i-043642e1d53b6ce4b', 'type': 't2.micro', 'keyname': 'id_rsa', 'security_group_ids': ['sg-0eb0b2d505594e52d']}], 'us-east-1b': [{'id': 'i-0b479e70c21c7d650', 'type': 't2.micro', 'keyname': 'id_rsa', 'security_group_ids': ['sg-0eb0b2d505594e52d']}], 'us-east-1c': [{'id': 'i-013c97a8cbc5bd512', 'type': 't2.micro', 'keyname': 'id_rsa', 'security_group_ids': ['sg-0eb0b2d505594e52d']}]}, 'ids': ['i-043642e1d53b6ce4b', 'i-0b479e70c21c7d650', 'i-013c97a8cbc5bd512']}

<TIMESTAMP> INFO
Find the load balancer that contains old AMI instances

<TIMESTAMP> INFO
Found LB: new-web-elb

<TIMESTAMP> INFO
Launching Instance: {'ami': 'ami-001e1c1159ccfe992', 'az': {'us-east-1d': [{'id': 'i-0790ed58340ece694', 'type': 't2.micro', 'keyname': 'id_rsa', 'security_group_ids': ['sg-0eb0b2d505594e52d']}]}, 'ids': ['i-0790ed58340ece694']}

<TIMESTAMP> INFO
Launching Instance: {'ami': 'ami-001e1c1159ccfe992', 'az': {'us-east-1b': [{'id': 'i-08743018082c47837', 'type': 't2.micro', 'keyname': 'id_rsa', 'security_group_ids': ['sg-0eb0b2d505594e52d']}]}, 'ids': ['i-08743018082c47837']}

<TIMESTAMP> INFO
Launching Instance: {'ami': 'ami-001e1c1159ccfe992', 'az': {'us-east-1c': [{'id': 'i-0ed187edf4530505f', 'type': 't2.micro', 'keyname': 'id_rsa', 'security_group_ids': ['sg-0eb0b2d505594e52d']}]}, 'ids': ['i-0ed187edf4530505f']}

<TIMESTAMP> INFO
Instances were created. Waiting up to 600 seconds for them to come online

<TIMESTAMP> INFO
Instances online

<TIMESTAMP> INFO
Attempting to swap old and new instances in LB

<TIMESTAMP> INFO
Ensure that LB health check exists and add one if not

<TIMESTAMP> INFO
Added instances to LB: {'LoadBalancerName': 'new-web-elb', 'Instances': [{'InstanceId': 'i-08743018082c47837'}, {'InstanceId': 'i-0ed187edf4530505f'}, {'InstanceId': 'i-0790ed58340ece694'}]}

<TIMESTAMP> INFO
Waiting up to 120 seconds for new instances in LB to be healthy

<TIMESTAMP> ERROR
Failed to add instances to LB or healthchecks failed. Deregistering any new instances found.
Waiter InstanceInService failed: Max attempts exceeded

<TIMESTAMP> INFO
Ensuring Connection Draining is turned on

<TIMESTAMP> INFO
Enabling Connection Draining

<TIMESTAMP> INFO
Deregistering instances from LB: {'LoadBalancerName': 'new-web-elb', 'Instances': [{'InstanceId': 'i-08743018082c47837'}, {'InstanceId': 'i-0ed187edf4530505f'}, {'InstanceId': 'i-0790ed58340ece694'}]}

<TIMESTAMP> INFO
Waiting up to 120 seconds for instances in LB to be deregistered

<TIMESTAMP> ERROR
Error while trying to swap instances in LB:
Waiter InstanceInService failed: Max attempts exceeded

<TIMESTAMP> WARNING
Attempting to terminate new instances due to error

<TIMESTAMP> INFO
Terminate the specified instance IDs & verify they no longer exist.

<TIMESTAMP> INFO
Successfully sent request to terminate instance:
[{'CurrentState': {'Code': 32, 'Name': 'shutting-down'}, 'InstanceId': 'i-08743018082c47837', 'PreviousState': {'Code': 16, 'Name': 'running'}}]

<TIMESTAMP> INFO
Successfully sent request to terminate instance:
[{'CurrentState': {'Code': 32, 'Name': 'shutting-down'}, 'InstanceId': 'i-0ed187edf4530505f', 'PreviousState': {'Code': 16, 'Name': 'running'}}]

<TIMESTAMP> INFO
Successfully sent request to terminate instance:
[{'CurrentState': {'Code': 32, 'Name': 'shutting-down'}, 'InstanceId': 'i-0790ed58340ece694', 'PreviousState': {'Code': 16, 'Name': 'running'}}]

<TIMESTAMP> INFO
Waiting up to 600 seconds for instances to be terminated

<TIMESTAMP> INFO
Success: New instances have been terminated. Deployment Rolled Back.
```
