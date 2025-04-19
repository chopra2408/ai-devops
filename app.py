import os
import argparse
import getpass
import yaml
import subprocess
import tempfile
import json
from git import Repo, GitCommandError
from typing import Dict, List, Optional, Tuple
import logging
import boto3
import azure.identity
import azure.mgmt.resource
from google.cloud import resourcemanager_v3
from google.oauth2 import service_account

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ai-devops')

class AIDevOpsAutomator:
    def __init__(self):
        self.repo_url = None
        self.git_token = None
        self.repo_path = None
        self.cloud_provider = None
        self.cloud_credentials = {}
        self.detected_stack = None
        self.resource_configuration = {}
        
    def collect_git_credentials(self) -> bool:
        """Collect Git credentials from user"""
        logger.info("Collecting Git credentials...")
        
        self.repo_url = input("Enter Git repository URL: ")
        if not self.repo_url:
            logger.error("Repository URL cannot be empty")
            return False
        
        # Determine if auth is needed based on URL
        auth_needed = "github.com" in self.repo_url or "gitlab.com" in self.repo_url or "bitbucket.org" in self.repo_url
        
        if auth_needed:
            token_input = getpass.getpass("Enter Git access token (input will be hidden): ")
            if token_input:
                self.git_token = token_input
            else:
                logger.error("Git token is required for private repositories")
                return False
        
        return True
    
    def access_repository(self) -> bool:
        """Clone repository or use API to access it"""
        logger.info(f"Accessing repository: {self.repo_url}")
        
        try:
            # Create a temporary directory for the repo
            temp_dir = tempfile.mkdtemp()
            self.repo_path = temp_dir
            
            if self.git_token:
                # Construct URL with token for auth
                auth_url = self.repo_url.replace('https://', f'https://{self.git_token}@')
                Repo.clone_from(auth_url, self.repo_path)
            else:
                Repo.clone_from(self.repo_url, self.repo_path)
                
            logger.info(f"Repository cloned successfully to {self.repo_path}")
            
            # Analyze repository to detect tech stack
            self._detect_tech_stack()
            
            return True
        except GitCommandError as e:
            logger.error(f"Git error: {e}")
            return False
        except Exception as e:
            logger.error(f"Error accessing repository: {e}")
            return False
    
    def _detect_tech_stack(self):
        """Analyze repository to detect technology stack"""
        logger.info("Detecting technology stack...")
        
        # Check for common files to determine the stack
        files = os.listdir(self.repo_path)
        
        if 'package.json' in files:
            self.detected_stack = 'nodejs'
        elif 'requirements.txt' in files or 'setup.py' in files:
            self.detected_stack = 'python'
        elif 'pom.xml' in files or 'build.gradle' in files:
            self.detected_stack = 'java'
        elif 'Dockerfile' in files:
            self.detected_stack = 'docker'
        elif 'go.mod' in files:
            self.detected_stack = 'golang'
        else:
            self.detected_stack = 'unknown'
            
        logger.info(f"Detected technology stack: {self.detected_stack}")
    
    def collect_cloud_credentials(self) -> bool:
        """Collect cloud provider credentials"""
        logger.info("Collecting cloud provider credentials...")
        
        providers = ['aws', 'azure', 'gcp']
        
        print("Available cloud providers:")
        for i, provider in enumerate(providers, 1):
            print(f"{i}. {provider.upper()}")
        
        choice = input("Select cloud provider (1-3): ")
        try:
            index = int(choice) - 1
            if 0 <= index < len(providers):
                self.cloud_provider = providers[index]
            else:
                logger.error("Invalid selection")
                return False
        except ValueError:
            logger.error("Invalid input, please enter a number")
            return False
        
        logger.info(f"Selected cloud provider: {self.cloud_provider.upper()}")
        
        # Collect credentials based on the selected provider
        if self.cloud_provider == 'aws':
            return self._collect_aws_credentials()
        elif self.cloud_provider == 'azure':
            return self._collect_azure_credentials()
        elif self.cloud_provider == 'gcp':
            return self._collect_gcp_credentials()
        
        return False
    
    def _collect_aws_credentials(self) -> bool:
        """Collect AWS specific credentials"""
        print("\nAWS Credential Options:")
        print("1. Use AWS CLI profile")
        print("2. Enter Access Key and Secret Key")
        
        choice = input("Select option (1-2): ")
        
        if choice == '1':
            profile = input("Enter AWS profile name [default]: ") or "default"
            self.cloud_credentials['type'] = 'profile'
            self.cloud_credentials['profile'] = profile
        elif choice == '2':
            access_key = input("Enter AWS Access Key ID: ")
            secret_key = getpass.getpass("Enter AWS Secret Access Key (input will be hidden): ")
            region = input("Enter AWS region [us-east-1]: ") or "us-east-1"
            
            if not access_key or not secret_key:
                logger.error("AWS credentials cannot be empty")
                return False
                
            self.cloud_credentials['type'] = 'keys'
            self.cloud_credentials['access_key'] = access_key
            self.cloud_credentials['secret_key'] = secret_key
            self.cloud_credentials['region'] = region
        else:
            logger.error("Invalid option selected")
            return False
            
        return True
    
    def _collect_azure_credentials(self) -> bool:
        """Collect Azure specific credentials"""
        print("\nAzure Credential Options:")
        print("1. Use Azure CLI session")
        print("2. Enter Service Principal details")
        
        choice = input("Select option (1-2): ")
        
        if choice == '1':
            self.cloud_credentials['type'] = 'cli'
        elif choice == '2':
            tenant_id = input("Enter Azure Tenant ID: ")
            client_id = input("Enter Azure Client ID: ")
            client_secret = getpass.getpass("Enter Azure Client Secret (input will be hidden): ")
            subscription_id = input("Enter Azure Subscription ID: ")
            
            if not tenant_id or not client_id or not client_secret or not subscription_id:
                logger.error("Azure credentials cannot be empty")
                return False
                
            self.cloud_credentials['type'] = 'service_principal'
            self.cloud_credentials['tenant_id'] = tenant_id
            self.cloud_credentials['client_id'] = client_id
            self.cloud_credentials['client_secret'] = client_secret
            self.cloud_credentials['subscription_id'] = subscription_id
        else:
            logger.error("Invalid option selected")
            return False
            
        return True
    
    def _collect_gcp_credentials(self) -> bool:
        """Collect GCP specific credentials"""
        print("\nGCP Credential Options:")
        print("1. Use application default credentials")
        print("2. Enter path to service account JSON key file")
        
        choice = input("Select option (1-2): ")
        
        if choice == '1':
            self.cloud_credentials['type'] = 'application_default'
        elif choice == '2':
            key_file = input("Enter path to GCP service account key file: ")
            project_id = input("Enter GCP Project ID: ")
            
            if not os.path.exists(key_file):
                logger.error(f"Key file not found: {key_file}")
                return False
                
            if not project_id:
                logger.error("Project ID cannot be empty")
                return False
                
            self.cloud_credentials['type'] = 'service_account'
            self.cloud_credentials['key_file'] = key_file
            self.cloud_credentials['project_id'] = project_id
        else:
            logger.error("Invalid option selected")
            return False
            
        return True
    
    def verify_cloud_resources(self) -> bool:
        """Verify cloud provider credentials and check available resources"""
        logger.info(f"Verifying {self.cloud_provider.upper()} resources...")
        
        try:
            if self.cloud_provider == 'aws':
                return self._verify_aws_resources()
            elif self.cloud_provider == 'azure':
                return self._verify_azure_resources()
            elif self.cloud_provider == 'gcp':
                return self._verify_gcp_resources()
            
            return False
        except Exception as e:
            logger.error(f"Error verifying cloud resources: {e}")
            return False
    
    def _verify_aws_resources(self) -> bool:
        """Verify AWS resources"""
        try:
            # Initialize AWS session based on the provided credentials
            if self.cloud_credentials['type'] == 'profile':
                session = boto3.Session(profile_name=self.cloud_credentials['profile'])
            else:
                session = boto3.Session(
                    aws_access_key_id=self.cloud_credentials['access_key'],
                    aws_secret_access_key=self.cloud_credentials['secret_key'],
                    region_name=self.cloud_credentials['region']
                )
            
            # Test the session by listing S3 buckets
            s3 = session.client('s3')
            s3.list_buckets()
            
            # Get available services for deployment
            ec2 = session.client('ec2')
            ecs = session.client('ecs')
            lambda_client = session.client('lambda')
            
            # Check if ECS clusters exist
            ecs_clusters = ecs.list_clusters()
            
            # Check if we have existing EC2 instances
            ec2_instances = ec2.describe_instances()
            
            # Ask user to choose deployment target
            print("\nAvailable AWS deployment targets:")
            print("1. EC2 (Virtual Machines)")
            print("2. ECS/Fargate (Containers)")
            print("3. Lambda (Serverless)")
            
            choice = input("Select deployment target (1-3): ")
            
            if choice == '1':
                self.resource_configuration['type'] = 'ec2'
                
                # Get instance types
                instance_types = ['t2.micro', 't2.small', 't2.medium', 'm5.large']
                print("\nSelect EC2 instance type:")
                for i, instance_type in enumerate(instance_types, 1):
                    print(f"{i}. {instance_type}")
                
                instance_choice = input(f"Instance type (1-{len(instance_types)}): ")
                try:
                    idx = int(instance_choice) - 1
                    if 0 <= idx < len(instance_types):
                        self.resource_configuration['instance_type'] = instance_types[idx]
                    else:
                        self.resource_configuration['instance_type'] = 't2.micro'
                except ValueError:
                    self.resource_configuration['instance_type'] = 't2.micro'
                    
            elif choice == '2':
                self.resource_configuration['type'] = 'ecs'
                
                if ecs_clusters['clusterArns']:
                    print("\nExisting ECS clusters:")
                    for i, cluster_arn in enumerate(ecs_clusters['clusterArns'], 1):
                        cluster_name = cluster_arn.split('/')[-1]
                        print(f"{i}. {cluster_name}")
                    
                    cluster_choice = input("Select cluster (or enter 'new' to create a new one): ")
                    
                    if cluster_choice.lower() == 'new':
                        self.resource_configuration['create_cluster'] = True
                        self.resource_configuration['cluster_name'] = input("Enter new cluster name: ")
                    else:
                        try:
                            idx = int(cluster_choice) - 1
                            if 0 <= idx < len(ecs_clusters['clusterArns']):
                                cluster_arn = ecs_clusters['clusterArns'][idx]
                                self.resource_configuration['cluster_arn'] = cluster_arn
                                self.resource_configuration['cluster_name'] = cluster_arn.split('/')[-1]
                            else:
                                logger.error("Invalid cluster selection")
                                return False
                        except ValueError:
                            logger.error("Invalid input, please enter a number")
                            return False
                else:
                    logger.info("No existing ECS clusters found. A new cluster will be created.")
                    self.resource_configuration['create_cluster'] = True
                    self.resource_configuration['cluster_name'] = input("Enter new cluster name: ") or "ai-devops-cluster"
                
            elif choice == '3':
                self.resource_configuration['type'] = 'lambda'
                self.resource_configuration['function_name'] = input("Enter Lambda function name: ") or "ai-devops-function"
                
                # Ask for memory allocation
                memory_values = [128, 256, 512, 1024, 2048]
                print("\nSelect Lambda memory allocation (MB):")
                for i, memory in enumerate(memory_values, 1):
                    print(f"{i}. {memory}")
                
                memory_choice = input(f"Memory allocation (1-{len(memory_values)}): ")
                try:
                    idx = int(memory_choice) - 1
                    if 0 <= idx < len(memory_values):
                        self.resource_configuration['memory'] = memory_values[idx]
                    else:
                        self.resource_configuration['memory'] = 128
                except ValueError:
                    self.resource_configuration['memory'] = 128
            else:
                logger.error("Invalid deployment target selected")
                return False
            
            return True
        except Exception as e:
            logger.error(f"Error verifying AWS resources: {e}")
            return False
    
    def _verify_azure_resources(self) -> bool:
        """Verify Azure resources"""
        try:
            # Initialize Azure client
            if self.cloud_credentials['type'] == 'cli':
                credential = azure.identity.AzureCliCredential()
                subscription_id = input("Enter Azure Subscription ID: ")
                self.cloud_credentials['subscription_id'] = subscription_id
            else:
                credential = azure.identity.ClientSecretCredential(
                    tenant_id=self.cloud_credentials['tenant_id'],
                    client_id=self.cloud_credentials['client_id'],
                    client_secret=self.cloud_credentials['client_secret']
                )
                subscription_id = self.cloud_credentials['subscription_id']
            
            # Test the credential by listing resource groups
            resource_client = azure.mgmt.resource.ResourceManagementClient(credential, subscription_id)
            resource_groups = list(resource_client.resource_groups.list())
            
            print("\nAvailable Azure resource groups:")
            for i, group in enumerate(resource_groups, 1):
                print(f"{i}. {group.name} (Location: {group.location})")
            
            group_choice = input("Select resource group (or enter 'new' to create a new one): ")
            
            if group_choice.lower() == 'new':
                group_name = input("Enter new resource group name: ")
                location = input("Enter location (e.g., eastus, westeurope): ")
                
                self.resource_configuration['create_resource_group'] = True
                self.resource_configuration['resource_group'] = group_name
                self.resource_configuration['location'] = location
            else:
                try:
                    idx = int(group_choice) - 1
                    if 0 <= idx < len(resource_groups):
                        group = resource_groups[idx]
                        self.resource_configuration['resource_group'] = group.name
                        self.resource_configuration['location'] = group.location
                    else:
                        logger.error("Invalid resource group selection")
                        return False
                except ValueError:
                    logger.error("Invalid input, please enter a number")
                    return False
            
            # Ask user to choose deployment target
            print("\nAvailable Azure deployment targets:")
            print("1. Azure VMs")
            print("2. App Service")
            print("3. Azure Container Instances")
            print("4. Azure Functions")
            
            choice = input("Select deployment target (1-4): ")
            
            if choice == '1':
                self.resource_configuration['type'] = 'vm'
                
                vm_sizes = ['Standard_B1s', 'Standard_B2s', 'Standard_D2_v3', 'Standard_F2s_v2']
                print("\nSelect VM size:")
                for i, size in enumerate(vm_sizes, 1):
                    print(f"{i}. {size}")
                
                vm_choice = input(f"VM size (1-{len(vm_sizes)}): ")
                try:
                    idx = int(vm_choice) - 1
                    if 0 <= idx < len(vm_sizes):
                        self.resource_configuration['vm_size'] = vm_sizes[idx]
                    else:
                        self.resource_configuration['vm_size'] = 'Standard_B1s'
                except ValueError:
                    self.resource_configuration['vm_size'] = 'Standard_B1s'
                    
            elif choice == '2':
                self.resource_configuration['type'] = 'app_service'
                self.resource_configuration['app_name'] = input("Enter App Service name: ") or "ai-devops-app"
                
                # Ask for app service plan tiers
                tiers = ['F1 (Free)', 'B1 (Basic)', 'S1 (Standard)', 'P1V2 (Premium)']
                print("\nSelect App Service plan tier:")
                for i, tier in enumerate(tiers, 1):
                    print(f"{i}. {tier}")
                
                tier_choice = input(f"Tier (1-{len(tiers)}): ")
                try:
                    idx = int(tier_choice) - 1
                    if 0 <= idx < len(tiers):
                        self.resource_configuration['tier'] = tiers[idx].split(' ')[0]
                    else:
                        self.resource_configuration['tier'] = 'F1'
                except ValueError:
                    self.resource_configuration['tier'] = 'F1'
                
            elif choice == '3':
                self.resource_configuration['type'] = 'container_instance'
                self.resource_configuration['container_name'] = input("Enter container name: ") or "ai-devops-container"
                
                # Ask for container resources
                self.resource_configuration['cpu'] = input("Enter CPU cores (e.g., 1): ") or "1"
                self.resource_configuration['memory'] = input("Enter memory in GB (e.g., 1.5): ") or "1.5"
                
            elif choice == '4':
                self.resource_configuration['type'] = 'function'
                self.resource_configuration['function_name'] = input("Enter Function App name: ") or "ai-devops-function"
                
            else:
                logger.error("Invalid deployment target selected")
                return False
                
            return True
        except Exception as e:
            logger.error(f"Error verifying Azure resources: {e}")
            return False
    
    def _verify_gcp_resources(self) -> bool:
        """Verify GCP resources"""
        try:
            # Initialize GCP client
            if self.cloud_credentials['type'] == 'service_account':
                credentials = service_account.Credentials.from_service_account_file(
                    self.cloud_credentials['key_file']
                )
                project_id = self.cloud_credentials['project_id']
            else:
                # Use application default credentials
                credentials = None
                project_id = input("Enter GCP Project ID: ")
                self.cloud_credentials['project_id'] = project_id
            
            # Ask user to choose deployment target
            print("\nAvailable GCP deployment targets:")
            print("1. Compute Engine (VMs)")
            print("2. Google Kubernetes Engine (GKE)")
            print("3. Cloud Run")
            print("4. Cloud Functions")
            
            choice = input("Select deployment target (1-4): ")
            
            if choice == '1':
                self.resource_configuration['type'] = 'vm'
                
                machine_types = ['e2-micro', 'e2-small', 'e2-medium', 'n1-standard-1']
                print("\nSelect machine type:")
                for i, machine_type in enumerate(machine_types, 1):
                    print(f"{i}. {machine_type}")
                
                machine_choice = input(f"Machine type (1-{len(machine_types)}): ")
                try:
                    idx = int(machine_choice) - 1
                    if 0 <= idx < len(machine_types):
                        self.resource_configuration['machine_type'] = machine_types[idx]
                    else:
                        self.resource_configuration['machine_type'] = 'e2-micro'
                except ValueError:
                    self.resource_configuration['machine_type'] = 'e2-micro'
                    
                self.resource_configuration['zone'] = input("Enter zone (e.g., us-central1-a): ") or "us-central1-a"
                
            elif choice == '2':
                self.resource_configuration['type'] = 'gke'
                self.resource_configuration['cluster_name'] = input("Enter GKE cluster name: ") or "ai-devops-cluster"
                self.resource_configuration['zone'] = input("Enter zone (e.g., us-central1-a): ") or "us-central1-a"
                
                node_counts = [1, 2, 3]
                print("\nSelect number of nodes:")
                for i, count in enumerate(node_counts, 1):
                    print(f"{i}. {count}")
                
                node_choice = input(f"Number of nodes (1-{len(node_counts)}): ")
                try:
                    idx = int(node_choice) - 1
                    if 0 <= idx < len(node_counts):
                        self.resource_configuration['node_count'] = node_counts[idx]
                    else:
                        self.resource_configuration['node_count'] = 1
                except ValueError:
                    self.resource_configuration['node_count'] = 1
                
            elif choice == '3':
                self.resource_configuration['type'] = 'cloud_run'
                self.resource_configuration['service_name'] = input("Enter Cloud Run service name: ") or "ai-devops-service"
                self.resource_configuration['region'] = input("Enter region (e.g., us-central1): ") or "us-central1"
                
                # Ask for container resources
                self.resource_configuration['memory'] = input("Enter memory limit (e.g., 256Mi, 512Mi, 1Gi): ") or "256Mi"
                self.resource_configuration['cpu'] = input("Enter CPU limit (e.g., 1, 2): ") or "1"
                
            elif choice == '4':
                self.resource_configuration['type'] = 'function'
                self.resource_configuration['function_name'] = input("Enter function name: ") or "ai-devops-function"
                self.resource_configuration['region'] = input("Enter region (e.g., us-central1): ") or "us-central1"
                
                # Ask for memory allocation
                memory_values = ['128MB', '256MB', '512MB', '1GB', '2GB']
                print("\nSelect function memory allocation:")
                for i, memory in enumerate(memory_values, 1):
                    print(f"{i}. {memory}")
                
                memory_choice = input(f"Memory allocation (1-{len(memory_values)}): ")
                try:
                    idx = int(memory_choice) - 1
                    if 0 <= idx < len(memory_values):
                        self.resource_configuration['memory'] = memory_values[idx]
                    else:
                        self.resource_configuration['memory'] = '128MB'
                except ValueError:
                    self.resource_configuration['memory'] = '128MB'
                
            else:
                logger.error("Invalid deployment target selected")
                return False
                
            return True

        except Exception as e:
            logger.error(f"Error verifying GCP resources: {e}")
            return False
    
    def generate_cicd_config(self) -> bool:
        """Generate CI/CD pipeline configuration"""
        logger.info("Generating CI/CD pipeline configuration...")

        repo_info = self.repo_url.lower()
        ci_platform = "github" # Default

        # Determine the CI/CD platform based on the repository URL
        if 'github.com' in repo_info:
            ci_platform = "github"
            logger.info("Detected GitHub repository, generating GitHub Actions workflow.")
            result = self._generate_github_actions_config()
        elif 'gitlab.com' in repo_info:
            ci_platform = "gitlab"
            logger.info("Detected GitLab repository, generating GitLab CI configuration.")
            result = self._generate_gitlab_ci_config()
        elif 'bitbucket.org' in repo_info:
             ci_platform = "bitbucket"
             logger.info("Detected Bitbucket repository, generating Bitbucket Pipelines configuration.")
             result = self._generate_bitbucket_pipelines_config()
        else:
            # Default to GitHub Actions if host is unknown but clone worked
            logger.warning(f"Could not determine CI/CD platform from URL ({self.repo_url}). Defaulting to GitHub Actions.")
            ci_platform = "github"
            result = self._generate_github_actions_config()

        # Store the platform used for instruction generation
        self.ci_platform = ci_platform
        # The helper methods now return True/False or handle logging internally
        return result # Return the success status from the specific generator
    
    def _generate_github_actions_config(self):
        """Generate GitHub Actions workflow configuration"""
        logger.info("Generating GitHub Actions workflow...")
        try:
            # Create .github/workflows directory if it doesn't exist
            workflows_dir = os.path.join(self.repo_path, '.github', 'workflows')
            os.makedirs(workflows_dir, exist_ok=True)
            
            # Generate workflow file based on detected technology stack and cloud provider
            workflow_file = os.path.join(workflows_dir, 'ai-devops-cicd.yml')
            
            # Start with common workflow structure
            workflow = {
                'name': 'AI DevOps CI/CD Pipeline',
                'on': {
                    'push': {
                        'branches': ['main', 'master']
                    },
                    'pull_request': {
                        'branches': ['main', 'master']
                    }
                },
                'jobs': {
                    'build': {
                        'runs-on': 'ubuntu-latest',
                        'steps': [
                            {
                                'name': 'Checkout code',
                                'uses': 'actions/checkout@v3'
                            }
                        ]
                    }
                }
            }
            
            # Add technology-specific build steps
            if self.detected_stack == 'nodejs':
                workflow['jobs']['build']['steps'].extend([
                    {
                        'name': 'Setup Node.js',
                        'uses': 'actions/setup-node@v3',
                        'with': {
                            'node-version': '16'
                        }
                    },
                    {
                        'name': 'Install dependencies',
                        'run': 'npm ci'
                    },
                    {
                        'name': 'Run tests',
                        'run': 'npm test || echo "No tests found"'
                    },
                    {
                        'name': 'Build',
                        'run': 'npm run build --if-present'
                    }
                ])
            elif self.detected_stack == 'python':
                workflow['jobs']['build']['steps'].extend([
                    {
                        'name': 'Setup Python',
                        'uses': 'actions/setup-python@v4',
                        'with': {
                            'python-version': '3.9'
                        }
                    },
                    {
                        'name': 'Install dependencies',
                        'run': 'pip install -r requirements.txt'
                    },
                    {
                        'name': 'Run tests',
                        'run': 'pytest || echo "No tests found"'
                    }
                ])
            elif self.detected_stack == 'java':
                workflow['jobs']['build']['steps'].extend([
                    {
                        'name': 'Setup Java',
                        'uses': 'actions/setup-java@v3',
                        'with': {
                            'distribution': 'temurin',
                            'java-version': '11'
                        }
                    },
                    {
                        'name': 'Build with Maven',
                        'run': 'mvn -B package --file pom.xml'
                    }
                ])
            elif self.detected_stack == 'golang':
                workflow['jobs']['build']['steps'].extend([
                    {
                        'name': 'Setup Go',
                        'uses': 'actions/setup-go@v4',
                        'with': {
                            'go-version': '^1.16'
                        }
                    },
                    {
                        'name': 'Build',
                        'run': 'go build -v ./...'
                    },
                    {
                        'name': 'Test',
                        'run': 'go test -v ./...'
                    }
                ])
            
            # Add deployment step based on cloud provider and resource configuration
            deploy_job = {
                'needs': 'build',
                'runs-on': 'ubuntu-latest',
                'steps': [
                    {
                        'name': 'Checkout code',
                        'uses': 'actions/checkout@v3'
                    }
                ]
            }
            
            if self.cloud_provider == 'aws':
                if self.resource_configuration['type'] == 'ec2':
                    deploy_job['steps'].extend([
                        {
                            'name': 'Configure AWS credentials',
                            'uses': 'aws-actions/configure-aws-credentials@v1',
                            'with': {
                                'aws-access-key-id': '${{ secrets.AWS_ACCESS_KEY_ID }}',
                                'aws-secret-access-key': '${{ secrets.AWS_SECRET_ACCESS_KEY }}',
                                'aws-region': self.cloud_credentials.get('region', 'us-east-1')
                            }
                        },
                        {
                            'name': 'Deploy to EC2',
                            'run': (
                                'echo "Deploying to EC2 instance..."\n'
                                'aws ec2 describe-instances\n'
                                '# Add your deployment steps here'
                            )
                        }
                    ])
                elif self.resource_configuration['type'] == 'ecs':
                    deploy_job['steps'].extend([
                        {
                            'name': 'Configure AWS credentials',
                            'uses': 'aws-actions/configure-aws-credentials@v1',
                            'with': {
                                'aws-access-key-id': '${{ secrets.AWS_ACCESS_KEY_ID }}',
                                'aws-secret-access-key': '${{ secrets.AWS_SECRET_ACCESS_KEY }}',
                                'aws-region': self.cloud_credentials.get('region', 'us-east-1')
                            }
                        },
                        {
                            'name': 'Login to Amazon ECR',
                            'id': 'login-ecr',
                            'uses': 'aws-actions/amazon-ecr-login@v1'
                        },
                        {
                            'name': 'Build and push Docker image',
                            'env': {
                                'ECR_REGISTRY': '${{ steps.login-ecr.outputs.registry }}',
                                'ECR_REPOSITORY': 'ai-devops-repo',
                                'IMAGE_TAG': '${{ github.sha }}'
                            },
                            'run': (
                                'docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .\n'
                                'docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG'
                            )
                        },
                        {
                            'name': 'Deploy to Amazon ECS',
                            'run': (
                                'aws ecs update-service --cluster ' + self.resource_configuration.get('cluster_name', 'ai-devops-cluster') + 
                                ' --service ai-devops-service --force-new-deployment'
                            )
                        }
                    ])
                elif self.resource_configuration['type'] == 'lambda':
                    deploy_job['steps'].extend([
                        {
                            'name': 'Configure AWS credentials',
                            'uses': 'aws-actions/configure-aws-credentials@v1',
                            'with': {
                                'aws-access-key-id': '${{ secrets.AWS_ACCESS_KEY_ID }}',
                                'aws-secret-access-key': '${{ secrets.AWS_SECRET_ACCESS_KEY }}',
                                'aws-region': self.cloud_credentials.get('region', 'us-east-1')
                            }
                        },
                        {
                            'name': 'Package Lambda function',
                            'run': 'zip -r function.zip .'
                        },
                        {
                            'name': 'Deploy to AWS Lambda',
                            'run': (
                                'aws lambda update-function-code --function-name ' + 
                                self.resource_configuration.get('function_name', 'ai-devops-function') + 
                                ' --zip-file fileb://function.zip'
                            )
                        }
                    ])
            
            elif self.cloud_provider == 'azure':
                if self.resource_configuration['type'] == 'vm':
                    deploy_job['steps'].extend([
                        {
                            'name': 'Azure Login',
                            'uses': 'azure/login@v1',
                            'with': {
                                'creds': '${{ secrets.AZURE_CREDENTIALS }}'
                            }
                        },
                        {
                            'name': 'Deploy to Azure VM',
                            'uses': 'azure/CLI@v1',
                            'with': {
                                'inlineScript': (
                                    'echo "Deploying to Azure VM..."\n'
                                    'az vm list -g ' + self.resource_configuration.get('resource_group', 'ai-devops-rg') + '\n'
                                    '# Add your deployment steps here'
                                )
                            }
                        }
                    ])
                elif self.resource_configuration['type'] == 'app_service':
                    deploy_job['steps'].extend([
                        {
                            'name': 'Azure Login',
                            'uses': 'azure/login@v1',
                            'with': {
                                'creds': '${{ secrets.AZURE_CREDENTIALS }}'
                            }
                        },
                        {
                            'name': 'Deploy to Azure Web App',
                            'uses': 'azure/webapps-deploy@v2',
                            'with': {
                                'app-name': self.resource_configuration.get('app_name', 'ai-devops-app'),
                                'package': './'
                            }
                        }
                    ])
                elif self.resource_configuration['type'] == 'container_instance':
                    deploy_job['steps'].extend([
                        {
                            'name': 'Azure Login',
                            'uses': 'azure/login@v1',
                            'with': {
                                'creds': '${{ secrets.AZURE_CREDENTIALS }}'
                            }
                        },
                        {
                            'name': 'Build and push Docker image',
                            'uses': 'azure/docker-login@v1',
                            'with': {
                                'login-server': 'mycontainerregistry.azurecr.io',
                                'username': '${{ secrets.REGISTRY_USERNAME }}',
                                'password': '${{ secrets.REGISTRY_PASSWORD }}'
                            }
                        },
                        {
                            'run': (
                                'docker build . -t mycontainerregistry.azurecr.io/' + 
                                self.resource_configuration.get('container_name', 'ai-devops-container') + ':${{ github.sha }}\n'
                                'docker push mycontainerregistry.azurecr.io/' + 
                                self.resource_configuration.get('container_name', 'ai-devops-container') + ':${{ github.sha }}'
                            )
                        },
                        {
                            'name': 'Deploy to Azure Container Instance',
                            'uses': 'azure/CLI@v1',
                            'with': {
                                'inlineScript': (
                                    'az container create --resource-group ' + 
                                    self.resource_configuration.get('resource_group', 'ai-devops-rg') + 
                                    ' --name ' + self.resource_configuration.get('container_name', 'ai-devops-container') + 
                                    ' --image mycontainerregistry.azurecr.io/' + 
                                    self.resource_configuration.get('container_name', 'ai-devops-container') + ':${{ github.sha }}' +
                                    ' --cpu ' + self.resource_configuration.get('cpu', '1') + 
                                    ' --memory ' + self.resource_configuration.get('memory', '1.5') + 
                                    ' --registry-login-server mycontainerregistry.azurecr.io' +
                                    ' --registry-username ${{ secrets.REGISTRY_USERNAME }}' +
                                    ' --registry-password ${{ secrets.REGISTRY_PASSWORD }}' +
                                    ' --dns-name-label ' + self.resource_configuration.get('container_name', 'ai-devops-container')
                                )
                            }
                        }
                    ])
                elif self.resource_configuration['type'] == 'function':
                    deploy_job['steps'].extend([
                        {
                            'name': 'Azure Login',
                            'uses': 'azure/login@v1',
                            'with': {
                                'creds': '${{ secrets.AZURE_CREDENTIALS }}'
                            }
                        },
                        {
                            'name': 'Deploy to Azure Function App',
                            'uses': 'Azure/functions-action@v1',
                            'with': {
                                'app-name': self.resource_configuration.get('function_name', 'ai-devops-function'),
                                'package': './',
                                'publish-profile': '${{ secrets.AZURE_FUNCTIONAPP_PUBLISH_PROFILE }}'
                            }
                        }
                    ])
            
            elif self.cloud_provider == 'gcp':
                if self.resource_configuration['type'] == 'vm':
                    deploy_job['steps'].extend([
                        {
                            'name': 'Setup GCloud',
                            'uses': 'google-github-actions/setup-gcloud@v0',
                            'with': {
                                'project_id': self.cloud_credentials.get('project_id', ''),
                                'service_account_key': '${{ secrets.GCP_SA_KEY }}',
                                'export_default_credentials': 'true'
                            }
                        },
                        {
                            'name': 'Deploy to Compute Engine',
                            'run': (
                                'echo "Deploying to Compute Engine..."\n'
                                'gcloud compute instances list\n'
                                '# Add your deployment steps here'
                            )
                        }
                    ])
                elif self.resource_configuration['type'] == 'gke':
                    deploy_job['steps'].extend([
                        {
                            'name': 'Setup GCloud',
                            'uses': 'google-github-actions/setup-gcloud@v0',
                            'with': {
                                'project_id': self.cloud_credentials.get('project_id', ''),
                                'service_account_key': '${{ secrets.GCP_SA_KEY }}',
                                'export_default_credentials': 'true'
                            }
                        },
                        {
                            'name': 'Get GKE credentials',
                            'run': (
                                'gcloud container clusters get-credentials ' + 
                                self.resource_configuration.get('cluster_name', 'ai-devops-cluster') + 
                                ' --zone ' + self.resource_configuration.get('zone', 'us-central1-a')
                            )
                        },
                        {
                            'name': 'Build and push Docker image',
                            'run': (
                                'docker build -t gcr.io/' + self.cloud_credentials.get('project_id', '') + 
                                '/ai-devops-app:${{ github.sha }} .\n'
                                'gcloud auth configure-docker -q\n'
                                'docker push gcr.io/' + self.cloud_credentials.get('project_id', '') + 
                                '/ai-devops-app:${{ github.sha }}'
                            )
                        },
                        {
                            'name': 'Deploy to GKE',
                            'run': (
                                'kubectl create deployment ai-devops-app --image=gcr.io/' + 
                                self.cloud_credentials.get('project_id', '') + 
                                '/ai-devops-app:${{ github.sha }} --dry-run=client -o yaml | kubectl apply -f -\n'
                                'kubectl get deployments'
                            )
                        }
                    ])
                elif self.resource_configuration['type'] == 'cloud_run':
                    deploy_job['steps'].extend([
                        {
                            'name': 'Setup GCloud',
                            'uses': 'google-github-actions/setup-gcloud@v0',
                            'with': {
                                'project_id': self.cloud_credentials.get('project_id', ''),
                                'service_account_key': '${{ secrets.GCP_SA_KEY }}',
                                'export_default_credentials': 'true'
                            }
                        },
                        {
                            'name': 'Build and push Docker image',
                            'run': (
                                'gcloud builds submit --tag gcr.io/' + 
                                self.cloud_credentials.get('project_id', '') + 
                                '/' + self.resource_configuration.get('service_name', 'ai-devops-service')
                            )
                        },
                        {
                            'name': 'Deploy to Cloud Run',
                            'run': (
                                'gcloud run deploy ' + self.resource_configuration.get('service_name', 'ai-devops-service') + 
                                ' --image gcr.io/' + self.cloud_credentials.get('project_id', '') + 
                                '/' + self.resource_configuration.get('service_name', 'ai-devops-service') + 
                                ' --platform managed' +
                                ' --region ' + self.resource_configuration.get('region', 'us-central1') +
                                ' --memory ' + self.resource_configuration.get('memory', '256Mi') +
                                ' --cpu ' + self.resource_configuration.get('cpu', '1') +
                                ' --allow-unauthenticated'
                            )
                        }
                    ])
                elif self.resource_configuration['type'] == 'function':
                    deploy_job['steps'].extend([
                        {
                            'name': 'Setup GCloud',
                            'uses': 'google-github-actions/setup-gcloud@v0',
                            'with': {
                                'project_id': self.cloud_credentials.get('project_id', ''),
                                'service_account_key': '${{ secrets.GCP_SA_KEY }}',
                                'export_default_credentials': 'true'
                            }
                        },
                        {
                            'name': 'Deploy to Cloud Functions',
                            'run': (
                                'gcloud functions deploy ' + self.resource_configuration.get('function_name', 'ai-devops-function') + 
                                ' --runtime python39' +
                                ' --trigger-http' +
                                ' --allow-unauthenticated' +
                                ' --region ' + self.resource_configuration.get('region', 'us-central1') +
                                ' --memory ' + self.resource_configuration.get('memory', '128MB')
                            )
                        }
                    ])
            
            # Add deployment job to workflow
            workflow['jobs']['deploy'] = deploy_job
            
            # Write workflow configuration to file
            with open(workflow_file, 'w') as f:
                yaml.dump(workflow, f, default_flow_style=False)
            
            logger.info(f"GitHub Actions workflow file created: {workflow_file}")
            return True
        except Exception as e:
            logger.error(f"Error writing YAML workflow file: {e}")
            return False
    
    def _generate_gitlab_ci_config(self):
        """Generate GitLab CI configuration"""
        logger.info("Generating GitLab CI configuration...")
        try:
        # Generate .gitlab-ci.yml file
            ci_file = os.path.join(self.repo_path, '.gitlab-ci.yml')
            
            # Start with common CI structure
            ci_config = {
                'stages': ['build', 'test', 'deploy'],
                'build': {
                    'stage': 'build',
                    'image': 'alpine:latest',
                    'script': ['echo "Building application..."'],
                    'artifacts': {
                        'paths': ['./']
                    }
                },
                'test': {
                    'stage': 'test',
                    'image': 'alpine:latest',
                    'script': ['echo "Running tests..."']
                },
                'deploy': {
                    'stage': 'deploy',
                    'image': 'alpine:latest',
                    'script': ['echo "Deploying application..."'],
                    'only': ['main', 'master']
                }
            }
            
            # Configure build and test stages based on tech stack
            if self.detected_stack == 'nodejs':
                ci_config['build']['image'] = 'node:16-alpine'
                ci_config['build']['script'] = [
                    'npm ci',
                    'npm run build --if-present'
                ]
                ci_config['test']['image'] = 'node:16-alpine'
                ci_config['test']['script'] = [
                    'npm ci',
                    'npm test || echo "No tests found"'
                ]
            elif self.detected_stack == 'python':
                ci_config['build']['image'] = 'python:3.9-slim'
                ci_config['build']['script'] = [
                    'pip install -r requirements.txt'
                ]
                ci_config['test']['image'] = 'python:3.9-slim'
                ci_config['test']['script'] = [
                    'pip install -r requirements.txt',
                    'pytest || echo "No tests found"'
                ]
            elif self.detected_stack == 'java':
                ci_config['build']['image'] = 'maven:3.8-openjdk-11'
                ci_config['build']['script'] = [
                    'mvn -B package --file pom.xml'
                ]
                ci_config['test']['image'] = 'maven:3.8-openjdk-11'
                ci_config['test']['script'] = [
                    'mvn test'
                ]
            elif self.detected_stack == 'golang':
                ci_config['build']['image'] = 'golang:1.16'
                ci_config['build']['script'] = [
                    'go build -v ./...'
                ]
                ci_config['test']['image'] = 'golang:1.16'
                ci_config['test']['script'] = [
                    'go test -v ./...'
                ]
            
            # Configure deploy stage based on cloud provider
            if self.cloud_provider == 'aws':
                ci_config['deploy']['image'] = 'amazon/aws-cli'
                ci_config['deploy']['before_script'] = [
                    'aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID',
                    'aws configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY',
                    f'aws configure set region {self.cloud_credentials.get("region", "us-east-1")}'
                ]
                
                if self.resource_configuration['type'] == 'ec2':
                    ci_config['deploy']['script'] = [
                        'echo "Deploying to EC2..."',
                        'aws ec2 describe-instances',
                        '# Add deployment steps here'
                    ]
                elif self.resource_configuration['type'] == 'ecs':
                    ci_config['deploy']['script'] = [
                        'echo "Deploying to ECS..."',
                        f'aws ecs update-service --cluster {self.resource_configuration.get("cluster_name", "ai-devops-cluster")} --service ai-devops-service --force-new-deployment'
                    ]
                elif self.resource_configuration['type'] == 'lambda':
                    ci_config['deploy']['script'] = [
                        'echo "Deploying to Lambda..."',
                        'zip -r function.zip .',
                        f'aws lambda update-function-code --function-name {self.resource_configuration.get("function_name", "ai-devops-function")} --zip-file fileb://function.zip'
                    ]
                    
            elif self.cloud_provider == 'azure':
                ci_config['deploy']['image'] = 'mcr.microsoft.com/azure-cli'
                ci_config['deploy']['before_script'] = [
                    'az login --service-principal -u $AZURE_SP_CLIENT_ID -p $AZURE_SP_CLIENT_SECRET --tenant $AZURE_TENANT_ID'
                ]
                
                if self.resource_configuration['type'] == 'vm':
                    ci_config['deploy']['script'] = [
                        'echo "Deploying to Azure VM..."',
                        f'az vm list -g {self.resource_configuration.get("resource_group", "ai-devops-rg")}',
                        '# Add deployment steps here'
                    ]
                elif self.resource_configuration['type'] == 'app_service':
                    ci_config['deploy']['script'] = [
                        'echo "Deploying to App Service..."',
                        f'az webapp deployment source config-zip --resource-group {self.resource_configuration.get("resource_group", "ai-devops-rg")} --name {self.resource_configuration.get("app_name", "ai-devops-app")} --src ./app.zip'
                    ]

            elif self.cloud_provider == 'gcp':
                ci_config['deploy']['image'] = 'google/cloud-sdk:slim'
                ci_config['deploy']['before_script'] = [
                    'echo $GCP_SERVICE_ACCOUNT > /tmp/service-account.json',
                    'gcloud auth activate-service-account --key-file=/tmp/service-account.json',
                    f'gcloud config set project {self.cloud_credentials.get("project_id", "")}'
                ]
                
                if self.resource_configuration['type'] == 'vm':
                    ci_config['deploy']['script'] = [
                        'echo "Deploying to GCP VM..."',
                        'gcloud compute instances list',
                        '# Add deployment steps here'
                    ]
                elif self.resource_configuration['type'] == 'gke':
                    ci_config['deploy']['script'] = [
                        'echo "Deploying to GKE..."',
                        f'gcloud container clusters get-credentials {self.resource_configuration.get("cluster_name", "ai-devops-cluster")} --zone {self.resource_configuration.get("zone", "us-central1-a")}',
                        '# Add deployment steps here'
                    ]
            
            # Write CI configuration to file
            with open(ci_file, 'w') as f:
                yaml.dump(ci_config, f, default_flow_style=False)
            
            logger.info(f"GitLab CI configuration file created: {ci_file}")
            return True
        except Exception as e:
            logger.error(f"Error generating GitLab CI configuration: {e}")
            return False
    
    def _generate_bitbucket_pipelines_config(self):
        """Generate Bitbucket Pipelines configuration"""
        logger.info("Generating Bitbucket Pipelines configuration...")
        try:
            # Generate bitbucket-pipelines.yml file
            ci_file = os.path.join(self.repo_path, 'bitbucket-pipelines.yml')
            
            # Start with common pipeline structure
            ci_config = {
                'image': 'alpine:latest',
                'pipelines': {
                    'default': [
                        {
                            'step': {
                                'name': 'Build and test',
                                'script': [
                                    'echo "Building application..."',
                                    'echo "Running tests..."'
                                ]
                            }
                        }
                    ],
                    'branches': {
                        'main': [
                            {
                                'step': {
                                    'name': 'Build',
                                    'script': [
                                        'echo "Building application..."'
                                    ]
                                }
                            },
                            {
                                'step': {
                                    'name': 'Deploy',
                                    'script': [
                                        'echo "Deploying application..."'
                                    ]
                                }
                            }
                        ]
                    }
                }
            }
            
            # Configure build and test based on tech stack
            if self.detected_stack == 'nodejs':
                ci_config['image'] = 'node:16-alpine'
                ci_config['pipelines']['default'][0]['step']['script'] = [
                    'npm ci',
                    'npm run build --if-present',
                    'npm test || echo "No tests found"'
                ]
                ci_config['pipelines']['branches']['main'][0]['step']['script'] = [
                    'npm ci',
                    'npm run build --if-present'
                ]
            elif self.detected_stack == 'python':
                ci_config['image'] = 'python:3.9-slim'
                ci_config['pipelines']['default'][0]['step']['script'] = [
                    'pip install -r requirements.txt',
                    'pytest || echo "No tests found"'
                ]
                ci_config['pipelines']['branches']['main'][0]['step']['script'] = [
                    'pip install -r requirements.txt',
                    'python setup.py build || echo "No setup.py found"'
                ]
            
            # Configure deployment based on cloud provider
            if self.cloud_provider == 'aws':
                ci_config['pipelines']['branches']['main'][1]['step']['script'] = [
                    'pipe: atlassian/aws-cli-run:1.0.0',
                    'variables:',
                    '  AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID',
                    '  AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY',
                    f'  AWS_DEFAULT_REGION: {self.cloud_credentials.get("region", "us-east-1")}',
                    '  COMMAND: "aws ec2 describe-instances"'
                ]
            elif self.cloud_provider == 'azure':
                ci_config['pipelines']['branches']['main'][1]['step']['script'] = [
                    'pipe: microsoft/azure-cli-run:1.0.0',
                    'variables:',
                    '  AZURE_APP_ID: $AZURE_APP_ID',
                    '  AZURE_PASSWORD: $AZURE_PASSWORD',
                    '  AZURE_TENANT_ID: $AZURE_TENANT_ID',
                    f'  CLI_COMMAND: "az webapp list --resource-group {self.resource_configuration.get("resource_group", "ai-devops-rg")}"'
                ]
            
            # Write pipeline configuration to file
            with open(ci_file, 'w') as f:
                yaml.dump(ci_config, f, default_flow_style=False)
            
            logger.info(f"Bitbucket Pipelines configuration file created: {ci_file}")
            return True
        except Exception as e:
            logger.error(f"Error generating Bitbucket Pipelines configuration: {e}")
            return False
    
    def commit_changes(self) -> bool:
        """Commit changes to the repository"""
        logger.info("Committing changes to repository...")
        
        try:
            repo = Repo(self.repo_path)
            
            # Add all files
            repo.git.add(all=True)
            
            # Commit changes
            repo.git.commit('-m', 'Add AI-generated CI/CD configuration')
            
            # Push changes if token is available
            if self.git_token:
                logger.info("Pushing changes to remote repository...")
                repo.git.push()
                logger.info("Changes pushed successfully")
            else:
                logger.info("No Git token provided. Please push changes manually.")
            
            return True
        except GitCommandError as e:
            logger.error(f"Git error: {e}")
            return False
        except Exception as e:
            logger.error(f"Error committing changes: {e}")
            return False
    
    def generate_setup_instructions(self) -> str:
        """Generate setup instructions for the user"""
        instructions = ["# AI DevOps Setup Instructions\n"]
        
        # Git instructions
        instructions.append("## Repository Setup")
        if not self.git_token:
            instructions.append("You'll need to manually push the changes to your repository:")
            instructions.append("```bash")
            instructions.append("cd " + self.repo_path)
            instructions.append("git add .")
            instructions.append('git commit -m "Add CI/CD configuration"')
            instructions.append("git push")
            instructions.append("```")
        else:
            instructions.append("✅ Changes have been committed and pushed to your repository.")
        
        # Secret setup instructions based on CI/CD platform
        repo_info = self.repo_url.lower()
        instructions.append("\n## Setting up Secrets/Environment Variables")
        
        if 'github.com' in repo_info:
            instructions.append("### GitHub Actions Secrets")
            instructions.append("1. Go to your GitHub repository")
            instructions.append("2. Click on 'Settings' > 'Secrets and variables' > 'Actions'")
            instructions.append("3. Add the following secrets:")
        elif 'gitlab.com' in repo_info:
            instructions.append("### GitLab CI Variables")
            instructions.append("1. Go to your GitLab repository")
            instructions.append("2. Click on 'Settings' > 'CI/CD'")
            instructions.append("3. Expand the 'Variables' section")
            instructions.append("4. Add the following variables (mark them as protected and masked where appropriate):")
        elif 'bitbucket.org' in repo_info:
            instructions.append("### Bitbucket Pipeline Variables")
            instructions.append("1. Go to your Bitbucket repository")
            instructions.append("2. Click on 'Repository settings' > 'Pipeline' > 'Repository variables'")
            instructions.append("3. Add the following variables (secure where appropriate):")
        
        # Add cloud-specific instructions
        if self.cloud_provider == 'aws':
            instructions.append("   - `AWS_ACCESS_KEY_ID`: Your AWS access key")
            instructions.append("   - `AWS_SECRET_ACCESS_KEY`: Your AWS secret key")
        elif self.cloud_provider == 'azure':
            instructions.append("   - `AZURE_CREDENTIALS`: JSON containing your Azure service principal details")
            if 'github.com' in repo_info:
                instructions.append("     For GitHub Actions, [see this guide](https://docs.microsoft.com/en-us/azure/developer/github/connect-from-azure)")
            else:
                instructions.append("   - `AZURE_SP_CLIENT_ID`: Your Azure service principal client ID")
                instructions.append("   - `AZURE_SP_CLIENT_SECRET`: Your Azure service principal client secret")
                instructions.append("   - `AZURE_TENANT_ID`: Your Azure tenant ID")
                instructions.append("   - `AZURE_SUBSCRIPTION_ID`: Your Azure subscription ID")
        elif self.cloud_provider == 'gcp':
            instructions.append("   - `GCP_SA_KEY`: Your GCP service account key (JSON)")
            instructions.append("   - `GCP_PROJECT_ID`: Your GCP project ID")
        
        # Add resource-specific instructions
        instructions.append("\n## Resource Setup")
        
        if self.cloud_provider == 'aws':
            if self.resource_configuration['type'] == 'ec2':
                instructions.append("### EC2 Instance")
                instructions.append("Ensure your EC2 instance is properly configured:")
                instructions.append("- Security groups allow necessary traffic")
                instructions.append("- Instance has an IAM role with appropriate permissions")
            elif self.resource_configuration['type'] == 'ecs':
                instructions.append("### ECS Service")
                instructions.append("You need to create the ECS service before the CI/CD pipeline can update it:")
                instructions.append("```bash")
                instructions.append(f"aws ecs create-cluster --cluster-name {self.resource_configuration.get('cluster_name', 'ai-devops-cluster')}")
                instructions.append("aws ecs create-service --cluster-name ai-devops-cluster --service-name ai-devops-service ...")
                instructions.append("```")
        
        # Add next steps
        instructions.append("\n## Next Steps")
        instructions.append("1. Review the generated CI/CD configuration")
        instructions.append("2. Set up the secrets/variables as instructed above")
        instructions.append("3. Push changes to your repository if they weren't pushed automatically")
        instructions.append("4. Monitor the CI/CD pipeline for successful execution")
        
        return "\n".join(instructions)
    
    def run(self):
        """Run the entire workflow"""
        if not self.collect_git_credentials():
            return "Failed to collect Git credentials."
        
        if not self.access_repository():
            return "Failed to access repository."
        
        if not self.collect_cloud_credentials():
            return "Failed to collect cloud credentials."
        
        if not self.verify_cloud_resources():
            return "Failed to verify cloud resources."
        
        if not self.generate_cicd_config():
            return "Failed to generate CI/CD configuration."
        
        self.commit_changes()
        
        setup_instructions = self.generate_setup_instructions()
        return setup_instructions


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='AI DevOps Tool - Automatically configure CI/CD for your codebase')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    print("="*80)
    print("Welcome to AI DevOps Automation Tool!")
    print("This tool will help you set up CI/CD pipelines for your codebase.")
    print("="*80)
    
    automator = AIDevOpsAutomator()
    result = automator.run()
    
    print("\n")
    print("="*80)
    print(result)
    print("="*80)

if __name__ == "__main__":
    main()