import logging
from pprint import pp
from typing import Any, Dict, Optional
import os

import boto3
from botocore.exceptions import ClientError, WaiterError

logger = logging.getLogger(__name__)

class SecurityGroupWrapper:
    """Encapsulates Amazon Elastic Compute Cloud (Amazon EC2) security group actions."""

    def __init__(self, ec2_client: boto3.client):
        """
        Initializes the SecurityGroupWrapper with an EC2 client and an optional security group ID.

        :param ec2_client: A Boto3 Amazon EC2 client. This client provides low-level
                           access to AWS EC2 services.
        """
        self.ec2_client = ec2_client
        self.default_security_group_id = None
        self.security_groups = []

    @classmethod
    def from_client(cls) -> "SecurityGroupWrapper":
        """
        Creates a SecurityGroupWrapper instance with a default EC2 client.

        :return: An instance of SecurityGroupWrapper initialized with the default EC2 client.
        """
        ec2_client = boto3.client("ec2",
                                  region_name=os.environ.get("AWS_DEFAULT_REGION", "us-west-1"),
                                  aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
                                  aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
                                  aws_session_token=os.environ.get("AWS_SESSION_TOKEN")
                                  )
        return cls(ec2_client)

    def create(self, group_name: str, group_description: str) -> str:
        """
        Creates a security group in the default virtual private cloud (VPC) of the current account.

        :param group_name: The name of the security group to create.
        :param group_description: The description of the security group to create.
        :return: The ID of the newly created security group.
        :raise Handles AWS SDK service-level ClientError, with special handling for ResourceAlreadyExists
        """
        try:
            response = self.ec2_client.create_security_group(
                GroupName=group_name, Description=group_description
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceAlreadyExists":
                logger.error(
                    f"Security group '{group_name}' already exists. Please choose a different name."
                )
            raise
        else:
            self.security_groups.append(response["GroupId"])
            return response["GroupId"]

    def exists(self, group_id) -> Optional[str]:
        """
        Retrieves the security group ID for the specified security group name.

        :param group_name: The name of the security group to retrieve.
        :return: The ID of the security group if found, otherwise None.
        """
        response = self.ec2_client.describe_security_groups(Filters=[{"Name": "group-id", "Values": [group_id]}])
        if response["SecurityGroups"]:
            security_group = response["SecurityGroups"][0]["GroupId"]
            return security_group
        else:
            return None

    def retrieve(self, group_id, ingress_ip) -> Optional[str]:
        """
        Retrieves the security group ID for the specified security group name.

        :param group_name: The name of the security group to retrieve.
        :return: The ID of the security group if found, otherwise None.
        """
        response = self.ec2_client.describe_security_groups(Filters=[{"Name": "group-id", "Values": [group_id]}])
        if response["SecurityGroups"]:
            security_group = response["SecurityGroups"][0]["GroupId"]
            print(f"Retrieved security group '{security_group}'")

            # Check if the ip is already authorized for SSH/22
            ip_permissions = response["SecurityGroups"][0]["IpPermissions"]

            tcp_22 = False
            for ip_permission in ip_permissions:
                print(ip_permission)
                if (ip_permission["FromPort"] == 22) and (f"{ingress_ip}/32" in [ip_range["CidrIp"] for ip_range in ip_permission["IpRanges"]]):
                    print(f"Security group '{security_group}' already has the specified rule.")
                    tcp_22 = True
            
            if not tcp_22:
                print(f"Authorizing ingress for SSH/22 to IP {ingress_ip}")
                self.add_rules(security_group, [
                    {
                        # SSH ingress open to only the specified IP address.
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": f"{ingress_ip}/32"}]
                    }
                ])
            if security_group not in self.security_groups:
                self.security_groups.append(security_group)
            return security_group
        else:
            return None

    def add_rules(self, security_group_id, ip_permissions) -> Optional[Dict[str, Any]]:
        """
        Adds a rule to the security group to allow access to SSH.

        :param security_group_id: The ID of the security group to update.
        :param ip_permissions: The IP permissions to add to the security group.
        :return: The response from the authorize_security_group_ingress() call.
        :raise ClientError: If the rule cannot be added to the security group.
        """
        try:
            response = self.ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id, IpPermissions=ip_permissions
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidPermission.Duplicate":
                logger.error(
                    f"Security group '{security_group_id}' already has the specified rule."
                )
            raise
        else:
            return response

    def describe(self, security_group_id: Optional[str] = None) -> bool:
        """
        Displays information about the specified security group or all security groups if no ID is provided.

        :param security_group_id: The ID of the security group to describe.
                                  If None, an open search is performed to describe all security groups.
        :returns: True if the description is successful.
        :raises ClientError: If there is an error describing the security group(s), such as an invalid security group ID.
        """
        try:
            paginator = self.ec2_client.get_paginator("describe_security_groups")

            if security_group_id is None:
                # If no ID is provided, return all security groups.
                page_iterator = paginator.paginate()
            else:
                page_iterator = paginator.paginate(GroupIds=[security_group_id])

            for page in page_iterator:
                for security_group in page["SecurityGroups"]:
                    print(f"Security group: {security_group['GroupName']}")
                    print(f"\tID: {security_group['GroupId']}")
                    print(f"\tVPC: {security_group['VpcId']}")
                    if security_group["IpPermissions"]:
                        print("Inbound permissions:")
                        pp(security_group["IpPermissions"])

            return True
        except ClientError as err:
            logger.error("Failed to describe security group(s).")
            if err.response["Error"]["Code"] == "InvalidGroup.NotFound":
                logger.error(
                    f"Security group {security_group_id} does not exist "
                    f"because the specified security group ID was not found."
                )
            raise

    def get_instance_security_groups(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the security groups associated with the specified EC2 instance.

        :param instance_id: The ID of the EC2 instance.
        :return: The security groups associated with the instance.
        :raises ClientError: If there is an error retrieving the security groups.
        """
        try:
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
            security_groups = response["Reservations"][0]["Instances"][0]["SecurityGroups"]
            return security_groups
        except ClientError as err:
            logger.error(f"Failed to retrieve security groups for instance {instance_id}.")
            raise

    def add_security_group_to_instance(self, instance_id, new_security_group_id):
        """
        Adds a security group to an already running EC2 instance.

        Args:
            instance_id (str): The ID of the EC2 instance.
            new_security_group_id (str): The ID of the security group to add.

        Returns:
            bool: True if the operation succeeds, False otherwise.

        Raises:
            Exception: If the operation fails.
        """
        try:
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
            instance = response["Reservations"][0]["Instances"][0]
            current_security_groups = [sg["GroupId"] for sg in instance["SecurityGroups"]]

            if new_security_group_id in current_security_groups:
                print(f"Security group {new_security_group_id} is already associated with the instance {instance_id}.")
                return False

            updated_security_groups = current_security_groups + [new_security_group_id]

            self.ec2_client.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=updated_security_groups
            )
            print(f"Security group {new_security_group_id} successfully added to instance {instance_id}.")
            return True

        except Exception as e:
            print(f"Error adding security group {new_security_group_id} to instance {instance_id}: {e}")
            return False

    def delete(self, security_group_id: str) -> bool:
        """
        Deletes the specified security group.

        :param security_group_id: The ID of the security group to delete. Required.

        :returns: True if the deletion is successful.
        :raises ClientError: If the security group cannot be deleted due to an AWS service error.
        """
        try:
            self.ec2_client.delete_security_group(GroupId=security_group_id)
            logger.info(f"Successfully deleted security group '{security_group_id}'")
            return True
        except ClientError as err:
            logger.error(f"Deletion failed for security group '{security_group_id}'")
            error_code = err.response["Error"]["Code"]

            if error_code == "InvalidGroup.NotFound":
                logger.error(
                    f"Security group '{security_group_id}' cannot be deleted because it does not exist."
                )
            elif error_code == "DependencyViolation":
                logger.error(
                    f"Security group '{security_group_id}' cannot be deleted because it is still in use."
                    " Verify that it is:"
                    "\n\t- Detached from resources"
                    "\n\t- Removed from references in other groups"
                    "\n\t- Removed from VPC's as a default group"
                )
            raise
        
    def delete_all(self) -> bool:
        """
        Terminates every security group in the account.
        """
        try:
            for security_group in self.security_groups:
                self.ec2_client.delete_security_group(GroupId=security_group)
            return True
        except ClientError as err:
            logger.error("Failed to terminate security groups.")
            raise