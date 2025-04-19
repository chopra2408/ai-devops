#!/usr/bin/env python3
import os
import getpass
import git  # Requires GitPython package (install via pip install GitPython)
import boto3  # Requires boto3 package (install via pip install boto3)
import botocore.exceptions
import yaml  # Requires PyYAML package (install via pip install pyyaml)

def get_git_repo_info():
    """
    Collects Git repository URL and an access token (or similar credentials) from the user.
    """
    print("Enter your Git repository URL:")
    repo_url = input("> ").strip()
    print("Enter your Git access token (if applicable):")
    git_token = getpass.getpass("> ")
    return repo_url, git_token

def clone_or_open_repo(repo_url, local_path="repo_clone"):
    """
    Clones the repository if not already cloned locally. If already present, then opens it.
    """
    try:
        # Try opening an existing repository
        repo = git.Repo(local_path)
        print("Local repository found.")
    except git.exc.InvalidGitRepositoryError:
        print("Cloning repository...")
        repo = git.Repo.clone_from(repo_url, local_path)
    return repo

def create_pipeline_yaml(local_path, pipeline_file=".github/workflows/ci-cd.yml"):
    """
    Creates a CI/CD pipeline YAML file (for GitHub Actions, for example) in the given repository.
    """
    full_path = os.path.join(local_path, pipeline_file)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    
    # Define a simple CI/CD pipeline structure
    pipeline_data = {
        'name': 'CI/CD Pipeline',
        'on': ['push', 'pull_request'],
        'jobs': {
            'build': {
                'runs-on': 'ubuntu-latest',
                'steps': [
                    {'name': 'Checkout Code', 'uses': 'actions/checkout@v2'},
                    {'name': 'Set up Python', 'uses': 'actions/setup-python@v2', 'with': {'python-version': '3.8'}},
                    {'name': 'Install Dependencies', 'run': 'pip install -r requirements.txt'},
                    {'name': 'Run Tests', 'run': 'pytest'},
                    {'name': 'Deploy', 'run': 'echo "Deploying application..."'}
                ]
            }
        }
    }
    
    # Write the pipeline configuration to file
    with open(full_path, "w") as f:
        yaml.dump(pipeline_data, f)
    
    print(f"Pipeline YAML created at {full_path}")

def push_changes(repo, commit_message="feat: add automated CI/CD pipeline setup"):
    """
    Adds all changes, commits them, and pushes to the remote repository.
    """
    repo.git.add(all=True)
    repo.index.commit(commit_message)
    origin = repo.remotes.origin
    origin.push()
    print("Changes successfully pushed to the remote repository.")

def get_aws_credentials():
    """
    Prompts the user to enter AWS credentials.
    """
    print("Enter AWS Access Key ID:")
    access_key = input("> ").strip()
    print("Enter AWS Secret Access Key:")
    secret_key = getpass.getpass("> ")
    return access_key, secret_key

def check_aws_resources(ec2_client, resource_tag_value):
    """
    Checks if the required resource exists.
    Here we search for an EC2 instance that has a specific tag value.
    """
    try:
        response = ec2_client.describe_instances(
            Filters=[{'Name': 'tag:ResourceID', 'Values': [resource_tag_value]}]
        )
        instances = [instance for reservation in response['Reservations']
                     for instance in reservation['Instances']]
        if instances:
            print("Required AWS resources are present.")
            return True
        else:
            print("AWS resources not found.")
            return False
    except botocore.exceptions.ClientError as error:
        print("Error checking AWS resources:", error)
        return False

def provision_aws_resource(ec2_client, resource_name="DemoInstance"):
    """
    Provisions a new AWS EC2 instance. Replace the AMI ID and settings with valid values.
    """
    try:
        response = ec2_client.run_instances(
            ImageId='ami-0abcdef1234567890',  # Replace with a valid AMI ID for your region
            MinCount=1,
            MaxCount=1,
            InstanceType='t2.micro',
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{'Key': 'Name', 'Value': resource_name},
                         {'Key': 'ResourceID', 'Value': 'MyDemoResource'}]
            }]
        )
        instance_id = response['Instances'][0]['InstanceId']
        print("EC2 instance launched with Instance ID:", instance_id)
    except botocore.exceptions.ClientError as error:
        print("Failed to launch EC2 instance:", error)

def main():
    # ---- Git and Repository Section ----
    repo_url, git_token = get_git_repo_info()
    repo = clone_or_open_repo(repo_url)
    create_pipeline_yaml(repo.working_tree_dir)
    push_changes(repo)
    
    # ---- Cloud Provider (AWS) Section ----
    access_key, secret_key = get_aws_credentials()
    
    # Create an AWS session
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name='us-east-1'  # You can modify or prompt for a region
    )
    ec2_client = session.client('ec2')
    resource_tag_value = "MyDemoResource"  # This should match with your resource naming convention
    
    # Check if the required resource exists; if not, provision it
    if not check_aws_resources(ec2_client, resource_tag_value):
        print("Proceeding with AWS resource provisioning...")
        provision_aws_resource(ec2_client)
    
    print("CI/CD setup and deployment process has been completed.")

if __name__ == "__main__":
    main()
