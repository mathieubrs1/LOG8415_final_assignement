import logging
import time
import random
import requests
import urllib.request
import uuid
import os
import paramiko

import boto3
from alive_progress import alive_bar
from rich.console import Console


from instance import EC2InstanceWrapper
from keypair import KeyPairWrapper
from security_group import SecurityGroupWrapper

logger = logging.getLogger(__name__)
console = Console()

# Read AWS credentials from environment file AWSaccess.txt
with open("AWS_access.txt", "r") as file:
    AWS_ACCESS_KEY_ID = file.readline().split("aws_access_key_id=")[1].strip()
    AWS_SECRET_ACCESS_KEY = file.readline().split("aws_secret_access_key=")[1].strip()
    AWS_SESSION_TOKEN = file.readline().split("aws_session_token=")[1].strip()

# Verify that the AWS credentials are set
if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY or not AWS_SESSION_TOKEN:
    console.print(
        "AWS credentials not found. Please ensure that the 'AWSaccess.txt' file contains the necessary credentials.",
        style="bold red",
    )
    exit(1)

INSTANCE_AMI = 'ami-0866a3c8686eaeeba' # Ubuntu Server 24.04 LTS (HVM), SSD Volume Type
INSTANCE_TYPE_MICRO = 't2.micro'
INSTANCE_TYPE_LARGE = 't2.large'

os.environ['AWS_DEFAULT_REGION'] = "us-east-1"
os.environ['AWS_ACCESS_KEY_ID'] = AWS_ACCESS_KEY_ID
os.environ['AWS_SECRET_ACCESS_KEY'] = AWS_SECRET_ACCESS_KEY
os.environ['AWS_SESSION_TOKEN'] = AWS_SESSION_TOKEN

os.environ['KEY_FILE_DIR'] = os.path.join(os.getcwd(), "keys")
PROJECT_NAME = "TP3"
INSTANCE_NAME_1 = "DB_Master"
INSTANCE_NAME_2 = "DB_Worker1"
INSTANCE_NAME_3 = "DB_Worker2"
INSTANCE_NAME_PROXY = "Proxy"
INSTANCE_NAME_GATEKEEPER = "Gatekeeper"
INSTANCE_NAME_TRUSTED_HOST = "TrustedHost"
MYSQL_USER = "root"
MYSQL_PASSWORD = "password"
REPLICA_USER = "replica_user"
REPLICA_PASSWORD = "replica_password"
PORT_APP = 8000
N_REQUESTS = 1000

console = Console()

class Scenario:
    """
    A scenario that demonstrates how to use Boto3 to manage Amazon EC2 resources.
    Covers creating a key pair, security group, launching an instance, associating
    an Elastic IP, and cleaning up resources.
    """

    def __init__(
        self,
        inst_wrapper: EC2InstanceWrapper,
        key_wrapper: KeyPairWrapper,
        sg_wrapper: SecurityGroupWrapper,
        remote_exec: bool = False
    ):
        """
        Initializes Scenario with the necessary AWS service wrappers.

        :param inst_wrapper: Wrapper for EC2 instance operations.
        :param key_wrapper: Wrapper for key pair operations.
        :param sg_wrapper: Wrapper for security group operations.
        :param remote_exec: Flag to indicate if the scenario is running in a remote execution
                            environment. Defaults to False. If True, the script won't prompt
                            for user interaction.
        """
        self.ec2_client = boto3.client("ec2")
        self.inst_wrapper = inst_wrapper
        self.key_wrapper = key_wrapper
        self.sg_wrapper = sg_wrapper
        self.remote_exec = remote_exec

    def create_and_list_key_pairs(self, key_name=f"{PROJECT_NAME}-KP-{uuid.uuid4().hex[:8]}") -> None:
        """
        Creates an RSA key pair for SSH access to the EC2 instance and lists available key pairs.
        """
        console.print("**Step 1: Create a Secure Key Pair**", style="bold cyan")

        with alive_bar(1, title=f"Creating Key Pair: {key_name}") as bar:
            self.key_wrapper.create(key_name)
            time.sleep(1) 
            bar()

        console.print(f"- **Private Key Saved to**: {self.key_wrapper.key_file_path}\n")

    def create_default_security_group(self, name=f"{PROJECT_NAME}-SG-{uuid.uuid4().hex[:8]}", ) -> None:
        """
        Creates a security group that controls access to the EC2 instance and adds a rule
        to allow SSH access from the user's current public IP address.
        """
        console.print("\n**Step 2: Create a Security Group : {name}**", style="bold cyan")

        with alive_bar(1, title=f"Creating Security Group: {name}") as bar:
            security_group_id = self.sg_wrapper.create(
                name, "Instances security"
            )
            time.sleep(1)
            bar()

        console.print(f"- **Security Group ID**: {security_group_id}\n")

        ip_response = urllib.request.urlopen("http://checkip.amazonaws.com")
        current_ip_address = ip_response.read().decode("utf-8").strip()
        console.print(
            "Let's add a rule to allow SSH only from your current IP address."
        )
        console.print(f"- **Your Public IP Address**: {current_ip_address}")
        console.print("- Automatically adding SSH rule...")
        ssh_ip_permissions = [
            {
                # SSH ingress open to only the specified IP address.
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": f"{current_ip_address}/32"}],
            }
        ]
        with alive_bar(1, title="Updating Security Group Rules") as bar:
            response = self.sg_wrapper.add_rules(security_group_id, ssh_ip_permissions)
            time.sleep(0.4)
            if response and response.get("Return"):
                self.sg_wrapper.default_security_group_id = security_group_id
                console.print("- **Security Group Rules Updated**.")
            else:
                console.print(
                    "- **Error**: Couldn't update security group rules.",
                    style="bold red",
                )
            bar()

        self.sg_wrapper.describe(security_group_id)                                      

    def create_instance(self, inst_type_choice, instance_ami) -> None:
        """
        Launches an EC2 instance using an specific AMI and the created key pair
        and security group. Displays instance details and SSH connection information.
        """

        with alive_bar(1, title="Creating Instances") as bar:
            self.inst_wrapper.create(
                instance_ami,
                inst_type_choice["InstanceType"],
                self.key_wrapper.key_pair["KeyName"],
                [self.sg_wrapper.default_security_group_id],
            )
            time.sleep(5)
            bar()

    def create_named_instance(self, instance_name, instance_type, instance_ami=INSTANCE_AMI) -> None:
        """
        Launches an EC2 instance using an specific AMI and the created key pair
        and security group. Displays instance details and SSH connection information.
        """
        console.print("\n**Step 3: Launch Your Instance**", style="bold cyan")
        console.print(
            "Let's create an instance from a specified AMI: {} and instance type : {}".format(instance_ami, instance_type)
        )

        inst_types = self.inst_wrapper.get_instance_types("x86_64")

        inst_type_choice = None
        for inst_type in inst_types:
            if inst_type["InstanceType"] == instance_type:
                console.print(f"- Found requested instance type: {inst_type['InstanceType']}")
                inst_type_choice = inst_type
                break
        
        if inst_type_choice is None:
            console.print(f"- Requested instance type '{instance_type}' not found.")
            return

        console.print("Creating an instance now...")

        self.create_instance(inst_type_choice, instance_ami)

        instance_index = len(self.inst_wrapper.instances) - 1

        self.inst_wrapper.add_tag(self.inst_wrapper.instances[instance_index]["InstanceId"], "Name", instance_name)
        self.inst_wrapper.instances[instance_index]["InstanceName"] = instance_name
        self.inst_wrapper.display()

        self._display_ssh_info(instance_index)

    def retrieve_instance(self, instance_name)-> bool:
        """
        Retrieves an instance with a specified name.

        :param instance_name: The name of the instance to retrieve.
        :return: The instance with the specified name, or None if no instance is found.
        """
        console.print("\n**Checking for existing ressources**", style="bold cyan")

        instance = self.inst_wrapper.exists(instance_name)
        if not instance:
            console.print(f"Instance with name {instance_name} not found")
            return False
        
        # Try to retrieve the keypair
        key_name = instance["KeyName"]
        key = self.key_wrapper.exists(key_name)
        if key:
            console.print(f"Found key pair {key_name}")
        else:
            console.print(f"Key pair {key_name} not found")
        
        # Try to retrieve the security group
        sg_id = instance["SecurityGroups"][0]["GroupId"]
        sg = self.sg_wrapper.exists(sg_id)
        if sg:
            console.print(f"Found security group {sg_id}")
            self.sg_wrapper.default_security_group_id = sg_id
        else:
            console.print(f"Security group {sg_id} not found")

        if instance and key and sg:
            self.key_wrapper.retrieve(key_name)
            ip_response = urllib.request.urlopen("http://checkip.amazonaws.com")
            current_ip_address = ip_response.read().decode("utf-8").strip()
            self.sg_wrapper.retrieve(sg_id, current_ip_address)
            self.inst_wrapper.retrieve(instance_name)
            return True
        else:
            console.print("One or more resources not found")
            self.inst_wrapper.remove_tag(instance["InstanceId"], "Name")

        return False
        
    def _display_ssh_info(self, index: int) -> None:
        """
        Displays SSH connection information for the user to connect to the EC2 instance.
        Handles the case where the instance does or does not have an associated public IP address.
        """
        if self.inst_wrapper.instances:
            instance = self.inst_wrapper.instances[index]
            instance_id = instance["InstanceId"]

            waiter = self.inst_wrapper.ec2_client.get_waiter("instance_running")
            console.print(
                "Waiting for the instance to be in a running state with a public IP...",
                style="bold cyan",
            )

            with alive_bar(1, title="Waiting for Instance to Start") as bar:
                waiter.wait(InstanceIds=[instance_id])
                time.sleep(1)
                bar()

            public_ip = self.get_public_ip(instance_id)
            if public_ip:
                console.print(
                    "\nTo connect via SSH, open another command prompt and run the following command:",
                    style="bold cyan",
                )
                console.print(
                    f"\tssh -i {self.key_wrapper.key_file_path} ubuntu@{public_ip}"
                )
            else:
                console.print(
                    "Instance does not have a public IP address assigned.",
                    style="bold red",
                )
        else:
            console.print(
                "No instance available to retrieve public IP address.",
                style="bold red",
            )
        
    def get_public_ip(self, instance_id):
        instance = self.inst_wrapper.ec2_client.describe_instances(
            InstanceIds=[instance_id]
            )["Reservations"][0]["Instances"][0]
        return instance.get("PublicIpAddress")
    
    def get_private_ip(self, instance_id):
        instance = self.inst_wrapper.ec2_client.describe_instances(
            InstanceIds=[instance_id]
        )["Reservations"][0]["Instances"][0]
        return instance.get("PrivateIpAddress")
    
    def execute_ssh_command(self, ssh: paramiko.SSHClient, command: str) -> bool:
        """Helper function to execute SSH commands."""
        session = ssh.get_transport().open_session()
        session.get_pty()
        session.exec_command(command)
    
        print(f"Executing: {command}")

        stderr = session.makefile_stderr("r", -1)

        exit_status = session.recv_exit_status()
        
        if exit_status != 0:
            error_message = stderr.read().decode()
            print(f"Command failed: {command}, Error: {error_message}")
            return False

        return True
    
    def execute_ssh_command_background_safe(self, ssh: paramiko.SSHClient, command: str) -> bool:
        """Helper function to execute SSH commands in the background."""
        print(f"Executing: {command}")
        stdin, stdout, stderr = ssh.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            print(f"Command failed: {command}, Error: {stderr.read().decode()}")
            return False
        return True
    
    def parse_master_status(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The file '{file_path}' does not exist.")
        
        with open(file_path, "r") as f:
            lines = f.readlines()
        
        headers = lines[0].strip().split('\t')
        values = lines[1].strip().split('\t')
        
        master_status = dict(zip(headers, values))
        return master_status
        
    def setup_and_benchmark_mysql(self, instance_id, instance_name):
        """
        Install MySQL on the specified instance.
        """
        console.print("\n**Step 4: Install MySQL on the instance**", style="bold cyan")
        os.chmod(os.path.dirname(self.key_wrapper.key_file_path), 0o700)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        #wait for the instance to be ready
        waiter = self.inst_wrapper.ec2_client.get_waiter("instance_running")
        console.print(
            "Waiting for the instance to be in a running state with a public IP...",
            style="bold cyan",
        )
        with alive_bar(1, title="Waiting for Instance to Start") as bar:
            waiter.wait(InstanceIds=[instance_id])
            time.sleep(5)
            bar()
        
        public_ip = self.get_public_ip(instance_id)

        ssh.connect(
            hostname=public_ip, 
            username="ubuntu",
            key_filename=self.key_wrapper.key_file_path
        )
        
        benchmark_file = "/tmp/sysbench_results.txt"

        commands = [
            # Update and install MySQL
            "sudo apt-get update -y",
            "sudo apt-get install -y mysql-server",
            # Set up MYSQL user with a password
            f"sudo mysql -e \"ALTER USER '{MYSQL_USER}'@'localhost' IDENTIFIED WITH 'mysql_native_password' BY '{MYSQL_PASSWORD}';\"",
            f"sudo mysql -u {MYSQL_USER} -p'{MYSQL_PASSWORD}' -e \"UPDATE mysql.user SET host = '%' WHERE user = '{MYSQL_USER}' AND host = 'localhost';\"",
            f"sudo mysql -u {MYSQL_USER} -p'{MYSQL_PASSWORD}' -e \"FLUSH PRIVILEGES;\"",
            "sudo systemctl enable mysql",
            "sudo systemctl start mysql",
            # Download and extract Sakila database
            "sudo apt-get install -y wget unzip",
            "sudo wget https://downloads.mysql.com/docs/sakila-db.zip -O /tmp/sakila-db.zip",
            "sudo unzip /tmp/sakila-db.zip -d /tmp",
            # Load Sakila database into MySQL
            f"sudo mysql -u {MYSQL_USER} -p'{MYSQL_PASSWORD}' -e \"SOURCE /tmp/sakila-db/sakila-schema.sql;SOURCE /tmp/sakila-db/sakila-data.sql;\"",
            # Use sysbench to benchmark the instance
            "sudo apt-get install sysbench -y",
            f"sudo sysbench /usr/share/sysbench/oltp_read_only.lua --mysql-db=sakila --mysql-user=\"{MYSQL_USER}\" --mysql-password=\"{MYSQL_PASSWORD}\" prepare",
            f"sudo sysbench /usr/share/sysbench/oltp_read_only.lua --mysql-db=sakila --mysql-user=\"{MYSQL_USER}\" --mysql-password=\"{MYSQL_PASSWORD}\" run > {benchmark_file}",
        ]
        
        if instance_name == INSTANCE_NAME_1:
            master_commands = [
                # set up the master instance for replication
                "sudo sed -i '/\[mysqld\]/a server-id=1\\nlog_bin=mysql-bin\\nbinlog_format=row' /etc/mysql/mysql.conf.d/mysqld.cnf",
                "sudo sed -i 's/^bind-address\s*=\s*127.0.0.1/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf",
                "sudo systemctl restart mysql",
                # create a replication user
                f"sudo mysql -u {MYSQL_USER} -p'{MYSQL_PASSWORD}' -e \"CREATE USER '{REPLICA_USER}'@'%' IDENTIFIED WITH 'mysql_native_password' BY '{REPLICA_PASSWORD}';\"",
                f"sudo mysql -u {MYSQL_USER} -p'{MYSQL_PASSWORD}' -e \"GRANT REPLICATION SLAVE ON *.* TO '{REPLICA_USER}'@'%';\"",
                f"sudo mysql -u {MYSQL_USER} -p'{MYSQL_PASSWORD}' -e \"FLUSH PRIVILEGES;\"",
                # Obtain binary log file and position for workers
                f"sudo mysql -u {MYSQL_USER} -p'{MYSQL_PASSWORD}' -e \"SHOW MASTER STATUS;\" > /tmp/master_status.txt",
            ]
            commands.extend(master_commands)
        else:
            master_ip = self.get_private_ip(self.inst_wrapper.instances[0]["InstanceId"])
            master_info = self.parse_master_status("./output/master_status.txt")
            master_log_file = master_info["File"]
            master_log_pos = master_info["Position"]
            worker_server_id = 2 if instance_name == INSTANCE_NAME_2 else 3 # 2 for worker1, 3 for worker2
            worker_commands = [
                # set up the worker instances for replication
                f"sudo sed -i '/\[mysqld\\]/a server-id={worker_server_id}\\nrelay_log=relay-bin' /etc/mysql/mysql.conf.d/mysqld.cnf",
                "sudo sed -i 's/^bind-address\s*=\s*127.0.0.1/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf",
                "sudo systemctl restart mysql",
                # set up replication from the master
                f"sudo mysql -u {MYSQL_USER} -p'{MYSQL_PASSWORD}' -e \"CHANGE MASTER TO MASTER_HOST='{master_ip}', MASTER_USER='{REPLICA_USER}', MASTER_PASSWORD='{REPLICA_PASSWORD}', MASTER_LOG_FILE='{master_log_file}', MASTER_LOG_POS={master_log_pos}, MASTER_SSL=0;\"",
                # start replication process
                f"sudo mysql -u {MYSQL_USER} -p'{MYSQL_PASSWORD}' -e \"START SLAVE;\"",
                # verify the replications status
                f"sudo mysql -u {MYSQL_USER} -p'{MYSQL_PASSWORD}' -e \"SHOW SLAVE STATUS\\G\" > /tmp/slave_status.txt",
            ]
            commands.extend(worker_commands)
        
        for command in commands:
            if not self.execute_ssh_command(ssh, command):
                break
            
        # Download the benchmark results
        os.makedirs("output", exist_ok=True)
        local_file_path = f"./output/sysbench_results_{instance_name}.txt"
        scp_command = f"scp -o StrictHostKeyChecking=no -i {self.key_wrapper.key_file_path} ubuntu@{public_ip}:{benchmark_file} {local_file_path}"
        os.system(scp_command)
        print(f"Downloaded benchmark results to {local_file_path}")
        
        if instance_name == INSTANCE_NAME_1:
            # Download the master status file
            master_status_file = "/tmp/master_status.txt"
            local_master_status_file = "./output/master_status.txt"
            scp_command = f"scp -o StrictHostKeyChecking=no -i {self.key_wrapper.key_file_path} ubuntu@{public_ip}:{master_status_file} {local_master_status_file}"
            os.system(scp_command)
            print(f"Downloaded master status to {local_master_status_file}")

        ssh.close()
        
    def setup_proxy(self, instance_id):
        """
        Setup the proxy on the specified instance.
        """
        console.print("\n**Step 5: Setup the Proxy**", style="bold cyan")
        os.chmod(os.path.dirname(self.key_wrapper.key_file_path), 0o700)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        #wait for the instance to be ready
        waiter = self.inst_wrapper.ec2_client.get_waiter("instance_running")
        console.print(
            "Waiting for the instance to be in a running state with a public IP...",
            style="bold cyan",
        )
        with alive_bar(1, title="Waiting for Instance to Start") as bar:
            waiter.wait(InstanceIds=[instance_id])
            time.sleep(5)
            bar()
        
        public_ip = self.get_public_ip(instance_id)
        # scp the proxyApp to the instance
        scp_command = f"scp -o StrictHostKeyChecking=no -i {self.key_wrapper.key_file_path} -r ./ProxyApp ubuntu@{public_ip}:~/"
        os.system(scp_command)
        print(f"Uploaded ProxyApp to {public_ip}")
        ssh.connect(
            hostname=public_ip, 
            username="ubuntu",
            key_filename=self.key_wrapper.key_file_path
        )
        
        # get ip of the 3 instances
        instances = self.inst_wrapper.instances
        ip_master = self.get_private_ip(instances[0]["InstanceId"])
        ip_worker1 = self.get_private_ip(instances[1]["InstanceId"])
        ip_worker2 = self.get_private_ip(instances[2]["InstanceId"])
        
        commands = [
            "sudo apt-get update -y",
            "sudo apt-get install -y python3-pip",
            "sudo apt install -y python3-pymysql python3-uvicorn python3-fastapi",
            "sudo chmod +x ~/ProxyApp/main.py",
            f"PORT={PORT_APP} IP_MASTER={ip_master} IP_WORKER1={ip_worker1} IP_WORKER2={ip_worker2} MYSQL_USER={MYSQL_USER} MYSQL_PASSWORD={MYSQL_PASSWORD} python3 ~/ProxyApp/main.py > fastapi.log 2>&1 &"
        ]
        for command in commands:
            if not self.execute_ssh_command_background_safe(ssh, command):
                break
        ssh.close()
        
    def setup_gatekeeper(self, instance_id, ip_forward):
        """
        Setup the gatekeeper on the specified instance.
        """
        console.print("\n**Step 7: Setup the Gatekeeper**", style="bold cyan")
        os.chmod(os.path.dirname(self.key_wrapper.key_file_path), 0o700)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        #wait for the instance to be ready
        waiter = self.inst_wrapper.ec2_client.get_waiter("instance_running")
        console.print(
            "Waiting for the instance to be in a running state with a public IP...",
            style="bold cyan",
        )
        with alive_bar(1, title="Waiting for Instance to Start") as bar:
            waiter.wait(InstanceIds=[instance_id])
            time.sleep(5)
            bar()
        
        public_ip = self.get_public_ip(instance_id)
        # scp the GatekeeperApp to the instance
        scp_command = f"scp -o StrictHostKeyChecking=no -i {self.key_wrapper.key_file_path} -r ./GatekeeperApp ubuntu@{public_ip}:~/"
        os.system(scp_command)
        print(f"Uploaded GatekeeperApp to {public_ip}")
        
        ssh.connect(
            hostname=public_ip, 
            username="ubuntu",
            key_filename=self.key_wrapper.key_file_path
        )
                
        commands = [
            "sudo apt-get update -y",
            "sudo apt-get install -y python3-pip",
            "sudo apt install -y python3-uvicorn python3-fastapi",
            "sudo apt install -y ufw",
            "sudo ufw allow 22",
            "sudo ufw allow 8000",
            "sudo chmod +x ~/GatekeeperApp/main.py",
            f"IP_FORWARD={ip_forward} PORT_FORWARD={PORT_APP} PORT_APP={PORT_APP} python3 ~/GatekeeperApp/main.py > fastapi.log 2>&1 &"
        ]
        for command in commands:
            if not self.execute_ssh_command_background_safe(ssh, command):
                break
        ssh.close()

    def create_db_cluster_security_group(self):
        # Create a security group for the DB cluster that allows only proxy to access it via port 3306
        with alive_bar(1, title="Creating Security Group for DB Cluster") as bar:
            security_group_id = self.sg_wrapper.create(
                f"{PROJECT_NAME}-SG-DBCLUSTER-{uuid.uuid4().hex[:8]}", "DB Cluster security"
            )
            time.sleep(1)
            bar()
        
        ip_proxy = self.get_private_ip(self.inst_wrapper.instances[3]["InstanceId"])
        ip_permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": 3306,
                "ToPort": 3306,
                "IpRanges": [{"CidrIp": f"{ip_proxy}/32"}],
            },
            {
                "IpProtocol": "icmp",
                "FromPort": -1,
                "ToPort": -1,
                "IpRanges": [{"CidrIp": f"{ip_proxy}/32"}],
            }
        ]
        with alive_bar(1, title="Updating Security Group Rules for DB Cluster") as bar:
            response = self.sg_wrapper.add_rules(security_group_id, ip_permissions)
            time.sleep(0.4)
            if response and response.get("Return"):
                for instance in self.inst_wrapper.instances[:3]: # 0: master, 1: worker1, 2: worker2
                    self.sg_wrapper.add_security_group_to_instance(instance["InstanceId"], security_group_id)
                console.print("- **Security Group Rules Updated**.")
            else:
                console.print(
                    "- **Error**: Couldn't update security group rules.",
                    style="bold red",
                )
            bar()
    
    def create_proxy_security_group(self):
        # Create a security group for the Proxy that allows only trusted host to access it via port 8000
        with alive_bar(1, title="Creating Security Group for Proxy") as bar:
            security_group_id = self.sg_wrapper.create(
                f"{PROJECT_NAME}-SG-PROXY-{uuid.uuid4().hex[:8]}", "Proxy security"
            )
            time.sleep(1)
            bar()
        
        ip_trusted_host = self.get_private_ip(self.inst_wrapper.instances[4]["InstanceId"])
        ip_permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": PORT_APP,
                "ToPort": PORT_APP,
                "IpRanges": [{"CidrIp": f"{ip_trusted_host}/32"}],
            }
        ]
        with alive_bar(1, title="Updating Security Group Rules for Proxy") as bar:
            response = self.sg_wrapper.add_rules(security_group_id, ip_permissions)
            time.sleep(0.4)
            if response and response.get("Return"):
                self.sg_wrapper.add_security_group_to_instance(self.inst_wrapper.instances[3]["InstanceId"], security_group_id)
                console.print("- **Security Group Rules Updated**.")
            else:
                console.print(
                    "- **Error**: Couldn't update security group rules.",
                    style="bold red",
                )
            bar()

    def create_trusted_host_security_group(self):
        # Create a security group for the Trusted Host that allows only gatekeeper to access it via port 8000
        with alive_bar(1, title="Creating Security Group for Trusted Host") as bar:
            security_group_id = self.sg_wrapper.create(
                f"{PROJECT_NAME}-SG-TRUSTEDHOST-{uuid.uuid4().hex[:8]}", "Trusted Host security"
            )
            time.sleep(1)
            bar()
        
        ip_gatekeeper = self.get_private_ip(self.inst_wrapper.instances[5]["InstanceId"])
        ip_permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": PORT_APP,
                "ToPort": PORT_APP,
                "IpRanges": [{"CidrIp": f"{ip_gatekeeper}/32"}],
            }
        ]
        with alive_bar(1, title="Updating Security Group Rules for Trusted Host") as bar:
            response = self.sg_wrapper.add_rules(security_group_id, ip_permissions)
            time.sleep(0.4)
            if response and response.get("Return"):
                self.sg_wrapper.add_security_group_to_instance(self.inst_wrapper.instances[4]["InstanceId"], security_group_id)
                console.print("- **Security Group Rules Updated**.")
            else:
                console.print(
                    "- **Error**: Couldn't update security group rules.",
                    style="bold red",
                )
            bar()

    def create_gatekeeper_security_group(self):
        # Create a security group for the Gatekeeper that opens port 8000 to the public
        with alive_bar(1, title="Creating Security Group for Gatekeeper") as bar:
            security_group_id = self.sg_wrapper.create(
                f"{PROJECT_NAME}-SG-GATEKEEPER-{uuid.uuid4().hex[:8]}", "Gatekeeper security"
            )
            time.sleep(1)
            bar()
        
        ip_permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": PORT_APP,
                "ToPort": PORT_APP,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ]
        with alive_bar(1, title="Updating Security Group Rules for Gatekeeper") as bar:
            response = self.sg_wrapper.add_rules(security_group_id, ip_permissions)
            time.sleep(0.4)
            if response and response.get("Return"):
                self.sg_wrapper.add_security_group_to_instance(self.inst_wrapper.instances[5]["InstanceId"], security_group_id)
                console.print("- **Security Group Rules Updated**.")
            else:
                console.print(
                    "- **Error**: Couldn't update security group rules.",
                    style="bold red",
                )
            bar()

    def create_security_groups(self):
        self.create_db_cluster_security_group()
        self.create_proxy_security_group()
        self.create_trusted_host_security_group()
        self.create_gatekeeper_security_group()

    def generate_read_query(self):
        return "SELECT count(*) FROM actor;"

    def generate_write_query(self):
        first_name = f"Name{random.randint(1, 1000)}"
        last_name = f"Surname{random.randint(1, 1000)}"
        return f"INSERT INTO actor (first_name, last_name) VALUES ('{first_name}', '{last_name}');"

    def send_query(self, query, implementation, url):
        try:
            response = requests.post(url, json={"query": query, "implementation": implementation})
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"error": str(e)}

    def load_test(self):
        gatekeeper_ip = self.get_public_ip(self.inst_wrapper.instances[5]["InstanceId"])
        url = f"http://{gatekeeper_ip}:{PORT_APP}/query"
        execution_times = {}
        dispersion_of_reads_dict = {}
        
        for implementation in range(1, 4): # 1: direct, 2: random, 3: ping
            dispersion_of_reads = {}
            read_success = 0
            write_success = 0
            print(f"Running benchmark for implementation {implementation}...")
            initial_time = time.time()
            for _ in range(N_REQUESTS):
                query = self.generate_read_query()
                result = self.send_query(query, implementation, url)
                if "error" not in result:
                    receiver = result["receiver"]
                    if receiver in dispersion_of_reads:
                        dispersion_of_reads[receiver] += 1
                    else:
                        dispersion_of_reads[receiver] = 1
                    read_success += 1
                else:
                    print(f"Read error: {result['error']}")
                    break

            for _ in range(N_REQUESTS):
                query = self.generate_write_query()
                result = self.send_query(query, implementation, url)
                if "error" not in result:
                    write_success += 1
                else:
                    print(f"Write error: {result['error']}")
                    break
                
            execution_times[implementation] = time.time() - initial_time
            dispersion_of_reads_dict[implementation] = dispersion_of_reads
            print(f"Read success: {read_success}/{N_REQUESTS}")
            print(f"Write success: {write_success}/{N_REQUESTS}")
        
        # output the data to ./output/benchmark_results.txt
        with open("./output/benchmark_results.txt", "w") as f:
            f.write(f"Execution times: {execution_times}\n")
            f.write(f"Dispersion of reads: {dispersion_of_reads_dict}\n")

    def cleanup(self) -> None:
        """
        Cleans up all the resources created during the scenario, including disassociating
        and releasing the Elastic IP, terminating the instance, deleting the security
        group, and deleting the key pair.
        """
        console.print("\n**Step 6: Clean Up Resources**", style="bold cyan")
        console.print("Cleaning up resources:")

        with alive_bar(1, title="Terminating Instances") as bar:
            self.inst_wrapper.terminate()
            time.sleep(1)
            bar()
        console.print("\t- **Terminated Instances**")
        
        with alive_bar(1, title="Deleting Securiy Groups") as bar:
            self.sg_wrapper.delete_all()
            time.sleep(1)
            bar()
        console.print("\t- **Deleted Security Groups**")

        console.print(f"- **Key Pair**: {self.key_wrapper.key_pair['KeyName']}")
        if self.key_wrapper.key_pair:
            with alive_bar(1, title="Deleting Key Pair") as bar:
                self.key_wrapper.delete(self.key_wrapper.key_pair["KeyName"])
                time.sleep(0.4)
                bar()

        console.print("\t- **Deleted Key Pair**")

    def run_scenario(self) -> None:
        """
        Executes the entire EC2 instance scenario: creates key pairs, security groups,
        launches an instance and cleans up all resources.
        """
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

        console.print("-" * 88)
        console.print(
            "Welcome to the Amazon Elastic Compute Cloud (Amazon EC2) get started with instances demo.",
            style="bold magenta",
        )
        console.print("-" * 88)
        
        if not self.retrieve_instance(INSTANCE_NAME_1):
            #1: create DB cluster (3 t2.micro instances)
            self.create_and_list_key_pairs()
            self.create_default_security_group()
            self.create_named_instance(INSTANCE_NAME_1, INSTANCE_TYPE_MICRO)
            self.create_named_instance(INSTANCE_NAME_2, INSTANCE_TYPE_MICRO)
            self.create_named_instance(INSTANCE_NAME_3, INSTANCE_TYPE_MICRO)
            for instance in self.inst_wrapper.instances:
                #2: setup DB cluster with replication (1 manager, 2 workers) and benchmark with sysbench
                print(f"Installing MySQL on instance {instance['InstanceName']}...")
                self.setup_and_benchmark_mysql(instance["InstanceId"], instance["InstanceName"])
        else:
            self.retrieve_instance(INSTANCE_NAME_2)
            self.retrieve_instance(INSTANCE_NAME_3)
        if not self.retrieve_instance(INSTANCE_NAME_PROXY):
            #3: implement Proxy pattern (1 instance t2.large) with 3 implementations
            self.create_named_instance(INSTANCE_NAME_PROXY, INSTANCE_TYPE_LARGE)
            self.setup_proxy(self.inst_wrapper.instances[3]["InstanceId"])  
        #4: implement Gatekeeper pattern (2 t2.large instances)
        if not self.retrieve_instance(INSTANCE_NAME_TRUSTED_HOST):
            self.create_named_instance(INSTANCE_NAME_TRUSTED_HOST, INSTANCE_TYPE_LARGE)
            self.setup_gatekeeper(self.inst_wrapper.instances[4]["InstanceId"], self.get_private_ip(self.inst_wrapper.instances[3]["InstanceId"]))
        if not self.retrieve_instance(INSTANCE_NAME_GATEKEEPER):
            self.create_named_instance(INSTANCE_NAME_GATEKEEPER, INSTANCE_TYPE_LARGE)
            self.setup_gatekeeper(self.inst_wrapper.instances[5]["InstanceId"], self.get_private_ip(self.inst_wrapper.instances[4]["InstanceId"]))
        #5: add security groups for the instances
        self.create_security_groups()
        #6: benchmark the results (1000 reads, 1000 writes for each implementation)
        if input("Press y to benchmark the results...") in ["y", "Y"]:
            self.load_test()
        #7: clean up
        if input("Press y to clean up...") in ["y", "Y"]:
            self.cleanup()

        console.print("\nThanks for watching!", style="bold green")
        console.print("-" * 88)

if __name__ == "__main__":
    scenario = Scenario(
        EC2InstanceWrapper.from_client(),
        KeyPairWrapper.from_client(),
        SecurityGroupWrapper.from_client(),
        remote_exec=False
    )
    try:
        scenario.run_scenario()
        input("Press Enter to continue...")
    except Exception:
        logging.exception("Something went wrong with the demo.")
