#!/usr/bin/env python3

import argparse
import os, sys
from collections import Counter
import logging
from inspect import stack
import inspect
try:
    import boto3
except Exception as e:
    print("Module unavailable: {}".format(e))
    sys.exit(1)

class Log():
    """Custom message logger, log to screen and to file"""
    fmt_file = '%(asctime)s %(levelname)-8s\n%(message)s\n'
    level = logging.INFO
    handler = logging.FileHandler('deploy.log')
    logging.basicConfig(format = fmt_file, level = level, handlers = [handler])

    #fmt_stdout = '%(levelname)-8s %(message)s\n'
    #fmt_stdout = '%(message)s\n'
    fmt_stdout = fmt_file
    stdout = logging.StreamHandler()
    stdout.setFormatter(logging.Formatter(fmt_stdout))
    logging.getLogger("").addHandler(stdout)

    @staticmethod
    def fatal(msg, code=1):
        """Log Fatal Error and exit with supplied error code"""
        logging.fatal("Error: {}".format(msg))
        sys.exit(code)

    @staticmethod
    def success(msg):
        """Log Successful message and exit"""
        logging.info("Success: {}".format(msg))
        sys.exit(0)

    @staticmethod
    def info(msg):
        """Log Informational message and continue"""
        logging.info(msg)

    @staticmethod
    def error(msg):
        """Log Error message and continue"""
        logging.error(msg)

    @staticmethod
    def warn(msg):
        """Log Warning message and continue"""
        logging.warning(msg)

    @staticmethod
    def fetch_docstring(objectname = "", ndx = 1):
        """Returns the docstring of the object that called it (based on the stack index)"""
        newobjectname = ".".join([ i for i in [objectname, stack()[ndx][3]] if i ])
        msg = eval('{}.__doc__'.format(newobjectname))
        return msg

    @staticmethod
    def docstring(objectname = ""):
        """Logs the docstring of the object that called it (based on the stack index)"""
        msg = Log.fetch_docstring(objectname, 2)
        Log.info("\n".join([ i.strip() for i in msg.split("\n") if i.strip() != "" ] ))

class ELB():
    """Manages interaction with the Load Balancer"""
    aws_session = None
    elb = None
    elb_client = None

    def __init__(self, aws_session, elb = None):
        self.aws_session = aws_session
        self.elb = elb
        self.elb_client = self.aws_session.client("elb")

    def find_elb_by_instances(self, instance_ids: list):
        """Uses instances_ids to locate the corresponding load balancer"""
        try:
            lbs = self.elb_client.describe_load_balancers()["LoadBalancerDescriptions"]
        except Exception as e:
            Log.fatal("Unable to obtain load balancer information:\n{}".format(e))

        if len(lbs) == 0:
            Log.fatal("No load balancers found. Aborting")

        for lb in lbs:
            lb_instances = set([ i["InstanceId"] for i in lb["Instances"] ])
            if lb_instances == set(instance_ids):
                return lb
            else:
                if lb_instances and (
                      lb_instances < set(instance_ids)
                      or set(instance_ids) < lb_instances
                      ):
                    msg = "Load balancer found but the number of instances "\
                        "it contains don't match the number found with "\
                        "old AMI IDs:\nLB: {}, Instances: {}"\
                        "\nOld AMI Instances: {}"
                    Log.fatal(msg.format(
                        lb['LoadBalancerName'], list(lb_instances)
                        , instance_ids
                    ))

        # If no LBs with old AMI instances found, log and exit
        Log.fatal("No load balancers found with instances with old AMI IDs")

    def find_load_balancer_by_instances(self, instance_ids: list):
        """Find the load balancer that contains old AMI instances"""
        Log.docstring(__class__.__name__)

        self.elb = self.find_elb_by_instances(instance_ids)
        Log.info("Found LB: {}".format(self.elb["LoadBalancerName"]))
        # TODO: Extend to support ELBv2 if no matching ELBs were found
        # find_elbv2_by_instances(instance_ids)

    def register_instances(self, instance_ids: list):
        """
        Add instances based on IDs to the load balancer and wait for them to be
        in service.
        """
        try:
            args = {
                "LoadBalancerName": self.elb["LoadBalancerName"]
                , "Instances": [ { 'InstanceId': i } for i in instance_ids ]
            }
            lb_instances = self.elb_client.register_instances_with_load_balancer(
                **args
            )["Instances"]
            Log.info("Added instances to LB: {}".format(args))
            delay, attempts = 15, 8
            msg = "Waiting up to {} seconds for new instances in LB to be healthy"
            Log.info(msg.format(delay*attempts))
            waiter = self.elb_client.get_waiter('instance_in_service')
            waiter.wait(
                LoadBalancerName = self.elb["LoadBalancerName"]
                , Instances = [ { 'InstanceId': i } for i in instance_ids ]
                , WaiterConfig = {
                    'Delay': delay,
                    'MaxAttempts': attempts
                }
            )
        except Exception as e:
            msg = "Failed to add instances to LB or healthchecks failed. "\
                "Deregistering any new instances found.\n{}".format(e)
            Log.error(msg)
            self.deregister_instances(instance_ids)
            raise
        return lb_instances

    def ensure_connection_draining_enabled(self):
        """
        Enable Connection Draining if it's turned off.
        This will allow instances automatically drain before being deregistered
        """

        Log.info("Ensuring Connection Draining is turned on")
        # Get LB Attributes
        lb_attributes = self.elb_client.describe_load_balancer_attributes(
            LoadBalancerName = self.elb["LoadBalancerName"]
        )["LoadBalancerAttributes"]

        # Conditionally Enabled ConnectionDraining
        if not lb_attributes["ConnectionDraining"]["Enabled"]:
            Log.info("Enabling Connection Draining")
            self.elb_client.modify_load_balancer_attributes(
                LoadBalancerName = self.elb["LoadBalancerName"]
                , LoadBalancerAttributes = {
                    'ConnectionDraining': { 'Enabled': True, 'Timeout': 300 }
                }
            )

    def deregister_instances(self, instance_ids: list):
        """
        Removes instances based on IDs from the load balancer and wait for them
        to be deregistered.
        """

        try:
            self.ensure_connection_draining_enabled()
            args = {
                "LoadBalancerName": self.elb["LoadBalancerName"]
                , "Instances": [ { 'InstanceId': i } for i in instance_ids ]
            }
            Log.info("Deregistering instances from LB: {}".format(args))
            lb_instances = self.elb_client.deregister_instances_from_load_balancer(
                **args
            )
            #)["Instances"]
            delay, attempts = 15, 8
            msg = "Waiting up to {} seconds for instances in LB to be deregistered"
            Log.info(msg.format(delay*attempts))
            waiter = self.elb_client.get_waiter('instance_deregistered')
            waiter.wait(
                LoadBalancerName = self.elb["LoadBalancerName"]
                , Instances = [ { 'InstanceId': i } for i in instance_ids ]
                , WaiterConfig = {
                    'Delay': delay,
                    'MaxAttempts': attempts
                }
            )
        except Exception as e:
            Log.error("Failed to deregister instances from LB")

        return lb_instances

    #def get_instance_health(self, instance_ids: list):
    #    return self.elb_client.describe_instance_health(
    #        LoadBalancerName = self.elb["LoadBalancerName"]
    #        , Instances = [ { 'InstanceId': i } for i in instance_ids ]
    #    )["InstanceStates"]

    def refresh_lb_info(self):
        elb = self.elb_client.describe_load_balancers(
            LoadBalancerNames = [ self.elb["LoadBalancerName"] ]
        )["LoadBalancerDescriptions"]
        if len(elb) == 0:
            raise Exception("No suitable load balancer found")
        self.elb = elb[0]

    def get_health_check_config(self):
        self.refresh_lb_info()
        # TODO: Test with an LB with no health check defined
        return self.elb["HealthCheck"]

    def add_health_check(self):
        resp = self.elb_client.configure_health_check(
            LoadBalancerName = self.elb["LoadBalancerName"]
            , HealthCheck={
                'Target': 'HTTP:80/',
                'Timeout': 5,
                'Interval': 6,
                'HealthyThreshold': 3,
                'UnhealthyThreshold': 3,
            }
        )
        Log.info("Health Check Added:\n{}".format(resp))

    def ensure_health_check_exists(self):
        """Ensure that LB health check exists and add one if not"""
        Log.docstring(__class__.__name__)

        health_check_config = self.get_health_check_config()
        if not health_check_config:
            self.add_health_check()

    def swap_instances(self, old_instance_ids: list, new_instance_ids: list):
        """
        - Do health checks in the LB since new instances don't go live until they pass the checks.
        - Add new instances to the load balancer.
        - Verify nodes are healthy/online in LB.
        - Enable Connection Draining if disabled
        - Deregister old instances from LB
        """
        try:
            Log.info("Attempting to swap old and new instances in LB")
            self.ensure_health_check_exists()
            self.register_instances(new_instance_ids)
            #new_instance_health = self.get_instance_health(new_instance_ids['ids'])
        except Exception as e:
            Log.error("Error while trying to swap instances in LB:\n{}".format(e))
            return False

        # TODO: cleanup: taken care of by register_instances waiters
        ## If the new instances are not all "InService", something went wrong.
        #if set({"InService"}) != set([ i["State"] for i in new_instance_health ]):
        #    Log.error("New instances failed health checks. Removing from LB.")
        #    self.deregister_instances(new_instance_ids)
        #    return False

        self.deregister_instances(old_instance_ids)
        return True

class Deploy():
    """
    Deploys changes that were saved in a new AMI to production by replacing old
    instances that were created from an old AMI ID.

    - The new instances are checked before they go live in the load balancer.
    - Old instances in the LB are drained and removed and then terminated.
    """

    # Initialize Class variables
    old_ami_id = new_ami_id = None
    aws_session = None
    old_instances = new_instances = None
    old_instances_meta = new_instances_meta = None
    ec2_client = None
    preserveInstance = False

    def __init__(self, aws_session, old_ami_id, new_ami_id, preserveInstance):
        self.aws_session = aws_session
        self.old_ami_id = old_ami_id
        self.new_ami_id = new_ami_id
        self.ec2_client = self.aws_session.client("ec2")
        self.preserveInstance = preserveInstance

    def ami_exists(self, ami_id):
        """Check if the given AMI exists"""

        try:
            self.aws_session.client('ec2').describe_images(ImageIds=[ami_id])
            return True
        except Exception:
            Log.fatal("Invalid AMI ID: {}".format(ami_id), 3)

    def verify_if_amis_exist(self):
        """Verifying that the given AMIs exist"""
        Log.docstring(__class__.__name__)

        amis = [ self.old_ami_id, self.new_ami_id ]
        [ self.ami_exists(ami) for ami in amis ]

    def get_instances_by_ami(self, ami):
        try:
            return self.ec2_client.describe_instances(MaxResults=1000
                , Filters=[
                    { "Name": "image-id" , "Values": [ami] }
                    , { "Name": "instance-state-name" , "Values": ["pending", "running"] }
                    ])["Reservations"]
        except:
            Log.error("Unable to retrieve instance info")
            return []

    def get_instance_meta(self, instances: list):
        if len(instances) > 0:
            summary = {
                'ami': ""
                , 'az': {}
            }
            for i in instances:
                for sub in i["Instances"]:
                    ami = sub["ImageId"]
                    zone = sub["Placement"]["AvailabilityZone"]
                    instance_type = sub["InstanceType"]
                    instance_id = sub["InstanceId"]
                    keyname = sub["KeyName"]
                    security_group_ids = [ i["GroupId"] for i in sub["SecurityGroups"] ]

                    summary['ami'] = ami
                    if zone not in summary['az']: #or instance_type not in summary['az']['type']):
                        summary['az'][zone] = []
                    if 'ids' not in summary:
                        summary['ids'] = []

                    summary['az'][zone].append({
                        'id': instance_id
                        , 'type': instance_type
                        , 'keyname': keyname
                        , 'security_group_ids': security_group_ids
                        })
                    summary['ids'].append(instance_id)
            return summary
        else:
            return {}

    def get_old_instance_info(self):
        """
        - Locate the instances with the old image ID.
        - Store the metadata about the instances.
        """
        self.old_instances = self.get_instances_by_ami(self.old_ami_id)
        if len(self.old_instances) == 0:
            Log.fatal("No instances found with old AMI ID")
        self.old_instances_meta = self.get_instance_meta(self.old_instances)
        Log.info ("Updated Old Instance Metadata: {}".format(self.old_instances_meta))

    def get_new_instance_info(self):
        """
        - Locate the instances with the new image ID.
        - Store the metadata about the instances.
        """
        self.new_instances = self.get_instances_by_ami(self.new_ami_id)
        self.new_instances_meta = self.get_instance_meta(self.new_instances)

    def fetch_instance_info(self):
        """Locate the instances with the old and new image IDs."""
        Log.docstring(__class__.__name__)

        self.get_old_instance_info()
        self.get_new_instance_info()
        if self.new_instances_meta:
            Log.info ("Updated New Instance Metadata: {}".format(self.new_instances_meta))

        # TODO: This might not be a problem
        #if len(self.old_instances) < len(self.new_instances):
        #    Log.fatal("More instances with new AMI ID than instances with old AMI ID")


    def create_new_instances(self):
        """
        - Create identical amounts and types of instances in each AZ based on
          the new image ID and the old instances' metadata.
        - Only add additional instances if an equivalent amount of new
          instances do not already exist. This allows for repeated runs of the
          script to only add missing servers (in case of errors) instead of
          constantly adding extra servers.
        - Wait for servers to be created
        """

        for zone in self.old_instances_meta['az']:
            old_instances_zone = self.old_instances_meta['az'][zone]
            old_types = [ i['type'] for i in old_instances_zone ]
            new_instances_zone = new_types = []
            if self.new_instances_meta and zone in self.new_instances_meta['az']:
                new_instances_zone = self.new_instances_meta['az'][zone]
                new_types = [ i['type'] for i in new_instances_zone ]

            missing = (Counter(old_types) - Counter(new_types))
            for instance_type in missing:
                for i in range(missing[instance_type]):
                    try:
                        old_instance = next(i for i in old_instances_zone if i['type'] == instance_type)
                        args = {
                            "ImageId": self.new_ami_id
                            , "Placement": { 'AvailabilityZone': zone }
                            , "InstanceType": instance_type
                            , "MaxCount": 1
                            , "MinCount": 1
                            , "SecurityGroupIds": old_instance["security_group_ids"]
                            , "KeyName": old_instance["keyname"]
                        }
                        # debug: examine data
                        # Log.fatal(args)
                        resp = self.ec2_client.run_instances(**args)
                        Log.info("Launching Instance: {}".format(self.get_instance_meta([resp])))
                    except Exception as e:
                        self.get_new_instance_info()
                        Log.error("Unable to launch instance:\n{}".format(e))
                        if self.new_instances_meta:
                            Log.info("Cleaning up new instances")
                            self.terminate_instances(self.new_instances_meta['ids'])
                        sys.exit(1)

        self.get_new_instance_info()
        try:
            delay, attempts = 15, 40
            msg = "Instances were created. Waiting up to {} seconds for them to come online"
            Log.info(msg.format(delay*attempts))
            waiter = self.ec2_client.get_waiter('instance_status_ok')
            waiter.wait(
                InstanceIds = self.new_instances_meta['ids']
                , IncludeAllInstances = True
                , WaiterConfig = { 'Delay': delay, 'MaxAttempts': attempts }
            )
            Log.info("Instances online")
        except:
            Log.error("Unable to create all instances. Cleaning up")
            self.terminate_instances(self.new_instances_meta['ids'])
            sys.exit(1)

    def terminate_instances(self, instance_ids : list):
        """ Terminate the specified instance IDs & verify they no longer exist."""
        Log.docstring(__class__.__name__)

        if self.preserveInstance:
            msg = "NOTE: Keeping instance for investigation purposes:\n{}"
            Log.info(msg.format(self.new_instances_meta['ids']))
            return

        """
        # Splitting the terminate task due to the following:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.terminate_instances
        If you specify multiple instances and the request fails (for example, because of a single incorrect instance ID), none of the instances are terminated.
        """
        failure = False
        for instance in instance_ids:
            try:
                resp = self.ec2_client.terminate_instances(
                    InstanceIds = [instance]
                )["TerminatingInstances"]
                Log.info ("Successfully sent request to terminate instance:\n{}".format(resp))
            except:
                failure = True
                Log.warn("Unable to terminate: {}".format(instance))

        try:
            delay, attempts = 15, 40
            msg = "Waiting up to {} seconds for instances to be terminated"
            Log.info(msg.format(delay*attempts))
            waiter = self.ec2_client.get_waiter('instance_terminated')
            waiter.wait(
                InstanceIds = instance_ids
                , WaiterConfig = { 'Delay': delay, 'MaxAttempts': attempts }
            )
            Log.info("Instances terminated successfully")
        except:
            Log.warn("Unable to wait to verify that instances are terminated: {}".format(instance))

        if failure:
            Log.fatal("Errors occurred while terminating instances")

    def run(self):
        # Verify that old and new IDs exist
        self.verify_if_amis_exist()

        # Locate the instances with the old and new image IDs.
        self.fetch_instance_info()

        # Find the load balancer with all the nodes that match the instances we found with the old image IDs. Return an error if the instance counts (load balancer nodes vs instances with old IDs) don't match.
        elb = ELB(self.aws_session)

        elb.find_load_balancer_by_instances(self.old_instances_meta['ids'])

        # TODO: Add instance comparison error check
        # Create identical amounts and types of instances in each AZ based on the new image ID and the old instances' metadata.
        self.create_new_instances()

        # Replace old instance with new instances in the LB with zero downtime
        swap_success = elb.swap_instances(self.old_instances_meta['ids'], self.new_instances_meta['ids'])
        if not swap_success:
            self.get_new_instance_info()
            if self.new_instances_meta:
                Log.warn("Attempting to terminate new instances due to error")
                self.terminate_instances(self.new_instances_meta['ids'])
                Log.success("New instances have been terminated. Deployment Rolled Back.")
            sys.exit(1)

        # How does this affect idempotence?
        # The number of new instances can be >= old instances. If so, add missing if any and cleanup old instances.
        self.terminate_instances(self.old_instances_meta['ids'])

def main(args):
    """
        Deploy new EC2 instances based on a new AMI and replace old instances
        that were built with an old AMI into your environment, doing health
        checks and updating the load balancer accordingly. Newly created
        instances will have the same availability zones and number of instances
        per AZ as old instances (i.e. 1 to 1 replacement of old and new instances).

        If a failure occurs, it will attempt to roll back changes such as
        deregistering newly added instances from the LB (always) and deleting
        newly created instances (default, but can be overridden)
    """

    desc = Log.fetch_docstring()
    def parse_args(args):
        """Parse and validate parameters"""
        parser = argparse.ArgumentParser(description=desc)
        parser.add_argument('old_ami_id', type=str, help='The old AMI ID that is used by instances')
        parser.add_argument('new_ami_id', type=str, help='The new AMI ID that you want to deploy')
        parser.add_argument('--keep', '-k', action='store_true', help="Don't terminate instances on failure (useful for investigations)")
        args = parser.parse_args(args)

        if args.old_ami_id == args.new_ami_id:
            parser.error("Old and new AMI IDs should be different")

        return args

    # Get arguments
    args = parse_args(args)

    Log.info("Logging to file: deploy.log")
    # Get AWS session
    def AuthAWS():
        creds_files = [ "~/.aws/credentials", "~/.aws/config" ]

        session = boto3.Session()
        creds = session.get_credentials()
        files = []

        for creds_file in creds_files:
            try:
                with open(os.path.expanduser(creds_file), 'r') as f:
                    files.append(f.name)
            except Exception:
                pass

        # Validate credentials file and credentials
        if len(files) < 1:
            Log.fatal("Unable to open AWS credentials file: {}".format(" or ".join(creds_files)))

        if creds == None:
            Log.fatal("Invalid Credentials in {}".format(" or ".join(files)))

        # return the session if valid
        return session

    msg = "Starting Deployment Process\nOld AMI ID: {}\nNew AMI ID: {}"
    Log.info(msg.format(args.old_ami_id, args.new_ami_id))

    # Get AWS session
    session = AuthAWS()

    # Run deployment
    deploy = Deploy(session, args.old_ami_id, args.new_ami_id, args.keep)
    deploy.run()
    Log.success ("Deployment Completed")

if __name__ == "__main__":
    main(sys.argv[1:])
