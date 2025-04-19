import os
import sys
import logging
import json
import tempfile
import stat
import argparse
import getpass
import zipfile
import time
import yaml
import shutil
from typing import Dict, List, Optional, Tuple
from git import Repo, GitCommandError

# Cloud SDK Imports
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    import azure.core.exceptions
    import azure.identity
    import azure.mgmt.resource
    import azure.mgmt.compute
    import azure.mgmt.network
    from google.oauth2 import service_account
    import google.api_core.exceptions as google_exceptions
    import google.auth.exceptions
    import google.cloud.compute_v1 as compute_v1
except ImportError as e:
    print(f"Warning: Some cloud SDK packages are missing: {str(e)}")
    print("Please install required packages using:")
    print("pip install boto3 azure-identity azure-mgmt-resource azure-mgmt-compute azure-mgmt-network google-cloud-compute google-auth")

# SSH Key Generation
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ai-devops')

# --- Helper Function for SSH Key ---
# --- Helper Function for SSH Key ---
# --- Helper Function for SSH Key ---
def generate_ssh_key_pair(key_filename_base="ai-devops-key"):
    """
    Generates or ensures an RSA SSH key pair exists locally.
    If private key exists but public is missing, regenerates public key.
    Returns private key path, public key content (str), and key name base.
    """
    private_key_path = f"./{key_filename_base}.pem"
    public_key_path = f"./{key_filename_base}.pub"
    public_key_content = None

    if os.path.exists(private_key_path):
        logger.info(f"Found existing private key: {private_key_path}")
        try:
            # Try loading the private key to ensure it's valid
            with open(private_key_path, "rb") as key_file:
                private_key = crypto_serialization.load_pem_private_key(
                    key_file.read(),
                    password=None, # Assuming no encryption
                    backend=crypto_default_backend()
                )

            # Check if public key file exists
            if os.path.exists(public_key_path):
                logger.info(f"Found existing public key: {public_key_path}")
                with open(public_key_path, "r") as f:
                    public_key_content = f.read()
            else:
                # Regenerate public key from private key if missing
                logger.warning(f"Public key {public_key_path} missing. Regenerating from private key.")
                public_key = private_key.public_key()
                public_key_ssh = public_key.public_bytes(
                    crypto_serialization.Encoding.OpenSSH,
                    crypto_serialization.PublicFormat.OpenSSH
                )
                with open(public_key_path, "wb") as f:
                    f.write(public_key_ssh)
                logger.info(f"Regenerated and saved public key to: {public_key_path}")
                public_key_content = public_key_ssh.decode('utf-8')

        except FileNotFoundError:
             # This shouldn't happen if os.path.exists was true, but handle defensively
             logger.error(f"Error reading existing private key file {private_key_path} even though it exists.")
             return None, None, None
        except (ValueError, TypeError, crypto_serialization.UnsupportedAlgorithm) as e:
             logger.error(f"Error loading existing private key {private_key_path}. It might be corrupt or password-protected (not supported): {e}")
             logger.error("Recommendation: Delete the existing .pem and .pub files and rerun the script.")
             return None, None, None

    else:
        # Neither private nor public key exists, generate new ones
        logger.info(f"Generating new SSH key pair: {key_filename_base}")
        try:
             key = rsa.generate_private_key(
                 backend=crypto_default_backend(),
                 public_exponent=65537,
                 key_size=2048
             )
             private_key_pem = key.private_bytes(
                 crypto_serialization.Encoding.PEM,
                 crypto_serialization.PrivateFormat.TraditionalOpenSSL,
                 crypto_serialization.NoEncryption()
             )
             public_key = key.public_key()
             public_key_ssh = public_key.public_bytes(
                 crypto_serialization.Encoding.OpenSSH,
                 crypto_serialization.PublicFormat.OpenSSH
             )

             # Save private key
             with open(private_key_path, "wb") as f:
                 f.write(private_key_pem)
             # Set permissions (read/write for owner only) - best effort on Windows
             try:
                  os.chmod(private_key_path, stat.S_IREAD | stat.S_IWRITE)
                  logger.info(f"Private key saved to: {private_key_path} (Permissions set)")
             except OSError:
                   logger.warning(f"Private key saved to: {private_key_path} (Could not set restrictive permissions on Windows)")


             # Save public key
             with open(public_key_path, "wb") as f:
                 f.write(public_key_ssh)
             logger.info(f"Public key saved to: {public_key_path}")

             public_key_content = public_key_ssh.decode('utf-8')

        except Exception as e:
            logger.error(f"Failed to generate new key pair: {e}", exc_info=True)
            return None, None, None

    # Ensure we have public key content before returning
    if not public_key_content:
         logger.error("Failed to obtain public key content.")
         return None, None, None

    return private_key_path, public_key_content, key_filename_base

class AIDevOpsAutomator:
    def __init__(self):
        self.repo_url = None
        self.git_token = None
        self.repo_path = None
        self.cloud_provider = None
        self.cloud_credentials = {}
        self.detected_stack = None
        self.resource_configuration = {}
        self.created_resource_details = {} # To store info about created resources
        self.ssh_key_paths = {} # To store paths to generated keys { 'private': path, 'public': path, 'key_name': name }


    # --- [ collect_git_credentials, access_repository, _detect_tech_stack remain largely the same ] ---
    def collect_git_credentials(self) -> bool:
        """Collect Git credentials from user"""
        logger.info("Collecting Git credentials...")

        self.repo_url = input("Enter Git repository URL: ")
        if not self.repo_url:
            logger.error("Repository URL cannot be empty")
            return False

        # Determine if auth is needed based on URL
        # More robust check: check if it starts with https:// and contains common private repo hosts
        is_likely_private = self.repo_url.startswith("https://") and \
                            any(host in self.repo_url for host in ["github.com", "gitlab.com", "bitbucket.org", "dev.azure.com"])

        # Or if it uses SSH format
        is_ssh_format = "@" in self.repo_url and ":" in self.repo_url

        if is_likely_private or is_ssh_format:
            use_token = input("Is this a private repository requiring authentication (token/password)? (y/N): ").lower() == 'y'
            if use_token:
                token_input = getpass.getpass("Enter Git access token/password (input will be hidden): ")
                if token_input:
                    self.git_token = token_input
                else:
                    logger.error("Git token/password is required for private repositories if specified.")
                    return False
            elif is_ssh_format:
                 logger.info("Assuming SSH key authentication for SSH URL format.")
                 self.git_token = None # Explicitly no token for SSH
            else:
                 logger.info("Proceeding without token for potentially public repository.")
                 self.git_token = None
        else:
            logger.info("Assuming public repository or anonymous access.")
            self.git_token = None # Public repo or other protocol

        return True

    def access_repository(self) -> bool:
        """Clone repository or use API to access it"""
        logger.info(f"Accessing repository: {self.repo_url}")

        try:
            # Create a temporary directory for the repo
            temp_dir = tempfile.mkdtemp(prefix="ai-devops-repo-")
            self.repo_path = temp_dir
            logger.info(f"Cloning repository into temporary directory: {self.repo_path}")

            clone_url = self.repo_url
            env = os.environ.copy()

            # Handle token authentication for HTTPS URLs
            if self.git_token and self.repo_url.startswith("https://"):
                # Construct URL with token for auth
                # Be careful with existing usernames in URL, though less common with tokens
                if "@" in self.repo_url.split("://")[1]:
                     logger.warning("URL already contains user info, token injection might conflict.")
                     # Attempt basic injection, might need refinement based on specific URL structure
                     proto, rest = self.repo_url.split("://")
                     clone_url = f"{proto}://oauth2:{self.git_token}@{rest.split('@', 1)[-1]}"
                else:
                     clone_url = self.repo_url.replace('https://', f'https://oauth2:{self.git_token}@')
                logger.debug(f"Using authenticated URL: {clone_url.replace(self.git_token, '***TOKEN***')}") # Avoid logging token

            # Handle SSH authentication (relies on existing SSH agent or keys)
            elif not self.git_token and "@" in self.repo_url and ":" in self.repo_url:
                 logger.info("Attempting clone using SSH protocol. Ensure your SSH key is configured.")
                 # Git command often needs ssh agent running, GitPython might handle some cases
                 # For more complex SSH auth (specific keys, passwords), os/subprocess might be needed
                 # Setting GIT_SSH_COMMAND can force a specific key, but is complex to manage here.
                 # Let GitPython try default SSH behavior first.
                 pass # Keep original URL

            # Clone the repository
            Repo.clone_from(clone_url, self.repo_path, env=env)

            logger.info(f"Repository cloned successfully to {self.repo_path}")

            # Analyze repository to detect tech stack
            self._detect_tech_stack()

            return True
        except GitCommandError as e:
            logger.error(f"Git error during clone: {e}")
            logger.error(f"Command: {' '.join(e.command)}")
            logger.error(f"Stderr: {e.stderr}")
            # Provide hints based on common errors
            if "Authentication failed" in e.stderr or "could not read Username" in e.stderr:
                 logger.error("Hint: Authentication failed. Check your repository URL and token/credentials.")
            elif "Repository not found" in e.stderr:
                 logger.error("Hint: Repository not found. Verify the URL is correct and you have access rights.")
            elif "Permission denied (publickey)" in e.stderr:
                 logger.error("Hint: SSH key authentication failed. Ensure your SSH key is added to your Git provider and ssh-agent is running.")
            return False
        except Exception as e:
            logger.error(f"Unexpected error accessing repository: {e}", exc_info=True)
            return False

    def _detect_tech_stack(self):
        """Analyze repository to detect technology stack"""
        logger.info("Detecting technology stack...")
        if not self.repo_path or not os.path.isdir(self.repo_path):
            logger.error("Repository path is not valid for stack detection.")
            self.detected_stack = 'unknown'
            return

        # Check for common files to determine the stack
        try:
            files = os.listdir(self.repo_path)

            if 'package.json' in files:
                self.detected_stack = 'nodejs'
            elif 'requirements.txt' in files or 'setup.py' in files or 'Pipfile' in files or 'pyproject.toml' in files:
                self.detected_stack = 'python'
            elif 'pom.xml' in files or 'build.gradle' in files or 'build.gradle.kts' in files:
                self.detected_stack = 'java' # Could be maven or gradle
            elif 'Dockerfile' in files:
                 # Docker can wrap anything, check for other clues *first*
                 if self.detected_stack is None: # Only set to docker if nothing else matched
                      self.detected_stack = 'docker'
                 else:
                      logger.info(f"Dockerfile found, but stack already detected as {self.detected_stack}. Keeping primary stack.")
            elif 'go.mod' in files:
                self.detected_stack = 'golang'
            elif any(f.endswith('.csproj') for f in files) or 'project.json' in files: # Basic C#/.NET check
                 self.detected_stack = 'dotnet'
            elif 'composer.json' in files: # PHP
                 self.detected_stack = 'php'
            elif 'Cargo.toml' in files: # Rust
                 self.detected_stack = 'rust'
            else:
                # Look deeper for clues, e.g., file extensions
                ext_counts = {}
                for item in os.listdir(self.repo_path):
                     item_path = os.path.join(self.repo_path, item)
                     if os.path.isfile(item_path):
                          _, ext = os.path.splitext(item)
                          if ext:
                               ext_counts[ext.lower()] = ext_counts.get(ext.lower(), 0) + 1

                if ext_counts:
                     # Simple heuristic: most frequent extension might indicate language
                     # This is very basic and can be wrong!
                     primary_ext = max(ext_counts, key=ext_counts.get)
                     if primary_ext == '.js': self.detected_stack = 'nodejs' # Could be frontend JS too
                     elif primary_ext == '.py': self.detected_stack = 'python'
                     elif primary_ext == '.java': self.detected_stack = 'java'
                     elif primary_ext == '.go': self.detected_stack = 'golang'
                     # Add more mappings as needed
                     else:
                          self.detected_stack = 'unknown'
                else:
                     self.detected_stack = 'unknown'

        except FileNotFoundError:
            logger.error(f"Repository path {self.repo_path} not found during stack detection.")
            self.detected_stack = 'unknown'
        except Exception as e:
            logger.error(f"Error detecting technology stack: {e}", exc_info=True)
            self.detected_stack = 'unknown'


        logger.info(f"Detected technology stack: {self.detected_stack}")

    # --- [ collect_cloud_credentials and its sub-methods remain the same ] ---
    def collect_cloud_credentials(self) -> bool:
        """Collect cloud provider credentials"""
        logger.info("Collecting cloud provider credentials...")

        providers = ['aws', 'azure', 'gcp']

        print("\nAvailable cloud providers:")
        for i, provider in enumerate(providers, 1):
            print(f"{i}. {provider.upper()}")

        choice = input(f"Select cloud provider (1-{len(providers)}): ")
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

        return False # Should not happen if validation is correct

    def _collect_aws_credentials(self) -> bool:
        """Collect AWS specific credentials"""
        print("\nAWS Credential Options:")
        print("1. Use AWS CLI profile (from ~/.aws/credentials or config)")
        print("2. Enter Access Key and Secret Key")
        print("3. Assume Role (requires base credentials - profile or keys)") # Added option

        choice = input("Select option (1-3): ")

        if choice == '1':
            # List available profiles (optional but helpful)
            try:
                profiles = boto3.Session().available_profiles
                if profiles:
                    print("Available profiles:", ", ".join(profiles))
                else:
                    print("No profiles found in default locations (~/.aws/credentials, ~/.aws/config).")
            except Exception as e:
                logger.warning(f"Could not list AWS profiles: {e}")

            profile = input("Enter AWS profile name [default]: ") or "default"
            region = input(f"Enter AWS region (optional, detected from profile or default '{boto3.Session().region_name or 'us-east-1'}'): ") or None # Allow detection
            self.cloud_credentials['type'] = 'profile'
            self.cloud_credentials['profile'] = profile
            self.cloud_credentials['region'] = region # Store explicitly even if None initially
        elif choice == '2':
            access_key = input("Enter AWS Access Key ID: ")
            secret_key = getpass.getpass("Enter AWS Secret Access Key (input will be hidden): ")
            region = input("Enter AWS region [us-east-1]: ") or "us-east-1"

            if not access_key or not secret_key:
                logger.error("AWS Access Key and Secret Key cannot be empty")
                return False

            self.cloud_credentials['type'] = 'keys'
            self.cloud_credentials['access_key'] = access_key
            self.cloud_credentials['secret_key'] = secret_key
            self.cloud_credentials['region'] = region
        elif choice == '3':
             # First, get base credentials
             print("Assume Role requires base credentials.")
             base_choice = input("Use profile (1) or keys (2) for base credentials? ")
             base_creds_ok = False
             if base_choice == '1':
                  profile = input("Enter AWS base profile name [default]: ") or "default"
                  self.cloud_credentials['base_type'] = 'profile'
                  self.cloud_credentials['base_profile'] = profile
                  base_creds_ok = True
             elif base_choice == '2':
                  access_key = input("Enter AWS base Access Key ID: ")
                  secret_key = getpass.getpass("Enter AWS base Secret Access Key: ")
                  if not access_key or not secret_key:
                       logger.error("Base AWS credentials cannot be empty")
                       return False
                  self.cloud_credentials['base_type'] = 'keys'
                  self.cloud_credentials['base_access_key'] = access_key
                  self.cloud_credentials['base_secret_key'] = secret_key
                  base_creds_ok = True
             else:
                  logger.error("Invalid base credential choice.")
                  return False

             if base_creds_ok:
                  role_arn = input("Enter the ARN of the role to assume: ")
                  session_name = input("Enter a role session name [ai-devops-session]: ") or "ai-devops-session"
                  region = input(f"Enter AWS region for the assumed role session [us-east-1]: ") or "us-east-1" # Region for the *session*

                  if not role_arn:
                       logger.error("Role ARN cannot be empty.")
                       return False

                  self.cloud_credentials['type'] = 'assume_role'
                  self.cloud_credentials['role_arn'] = role_arn
                  self.cloud_credentials['session_name'] = session_name
                  self.cloud_credentials['region'] = region
                  # Base creds already stored under 'base_type', 'base_profile'/'base_keys'
        else:
            logger.error("Invalid option selected")
            return False

        return True

    def _collect_azure_credentials(self) -> bool:
        """Collect Azure specific credentials"""
        print("\nAzure Credential Options:")
        print("1. Use Azure CLI Login (az login)")
        print("2. Enter Service Principal details")
        print("3. Use Managed Identity (if running on Azure service with MSI enabled)") # Added option

        choice = input("Select option (1-3): ")

        if choice == '1':
            # Need subscription ID even with CLI login
            subscription_id = input("Enter Azure Subscription ID (required): ")
            if not subscription_id:
                 logger.error("Subscription ID is required for Azure CLI interaction.")
                 return False
            self.cloud_credentials['type'] = 'cli'
            self.cloud_credentials['subscription_id'] = subscription_id
        elif choice == '2':
            tenant_id = input("Enter Azure Tenant ID: ")
            client_id = input("Enter Azure Client ID (Application ID): ")
            client_secret = getpass.getpass("Enter Azure Client Secret (input will be hidden): ")
            subscription_id = input("Enter Azure Subscription ID: ")

            if not tenant_id or not client_id or not client_secret or not subscription_id:
                logger.error("Azure Service Principal details (Tenant ID, Client ID, Client Secret, Subscription ID) cannot be empty")
                return False

            self.cloud_credentials['type'] = 'service_principal'
            self.cloud_credentials['tenant_id'] = tenant_id
            self.cloud_credentials['client_id'] = client_id
            self.cloud_credentials['client_secret'] = client_secret
            self.cloud_credentials['subscription_id'] = subscription_id
        elif choice == '3':
             # Need subscription ID for context
             subscription_id = input("Enter Azure Subscription ID (required for context): ")
             if not subscription_id:
                  logger.error("Subscription ID is required for context even with Managed Identity.")
                  return False
             # Optionally ask for user-assigned identity client ID
             msi_client_id = input("Enter Client ID of User-Assigned Managed Identity (optional, leave blank for system-assigned): ")
             self.cloud_credentials['type'] = 'managed_identity'
             self.cloud_credentials['subscription_id'] = subscription_id
             if msi_client_id:
                  self.cloud_credentials['msi_client_id'] = msi_client_id
             logger.info("Attempting to use Managed Identity. Ensure the environment supports it.")
        else:
            logger.error("Invalid option selected")
            return False

        return True

    def _collect_gcp_credentials(self) -> bool:
        """Collect GCP specific credentials"""
        print("\nGCP Credential Options:")
        print("1. Use Application Default Credentials (ADC) (e.g., gcloud auth application-default login, or Compute Engine metadata service)")
        print("2. Enter path to service account JSON key file")

        choice = input("Select option (1-2): ")

        if choice == '1':
            # ADC still needs a project ID
            project_id = input("Enter GCP Project ID (required for context): ")
            if not project_id:
                 logger.error("Project ID is required for GCP operations.")
                 return False
            self.cloud_credentials['type'] = 'application_default'
            self.cloud_credentials['project_id'] = project_id
            logger.info("Attempting to use Application Default Credentials. Ensure they are configured correctly.")
        elif choice == '2':
            key_file = input("Enter path to GCP service account key file (.json): ")
            # Don't need project ID explicitly if it's in the key file, but asking is good practice for confirmation/context
            project_id_from_user = input("Enter GCP Project ID (will use project from keyfile if found, otherwise uses this): ")

            if not os.path.exists(key_file):
                logger.error(f"Service account key file not found: {key_file}")
                return False
            if not key_file.lower().endswith('.json'):
                 logger.warning("Key file does not end with .json, ensure it is the correct format.")

            # Try to extract project ID from key file to make it easier for the user
            project_id_from_key = None
            try:
                 with open(key_file, 'r') as f:
                      key_data = json.load(f)
                      project_id_from_key = key_data.get('project_id')
                 if project_id_from_key:
                      logger.info(f"Detected Project ID '{project_id_from_key}' from key file.")
                      if project_id_from_user and project_id_from_user != project_id_from_key:
                           logger.warning(f"User-provided Project ID '{project_id_from_user}' differs from key file ID '{project_id_from_key}'. Using ID from key file.")
                      project_id = project_id_from_key
                 elif project_id_from_user:
                      logger.info("Using user-provided Project ID as it was not found in the key file.")
                      project_id = project_id_from_user
                 else:
                      logger.error("Project ID not found in key file and not provided by user. Cannot proceed.")
                      return False
            except json.JSONDecodeError:
                 logger.error(f"Could not parse key file {key_file}. Is it valid JSON?")
                 return False
            except Exception as e:
                 logger.error(f"Error reading key file {key_file}: {e}")
                 return False

            if not project_id: # Should be caught above, but double-check
                 logger.error("GCP Project ID is required.")
                 return False

            self.cloud_credentials['type'] = 'service_account'
            self.cloud_credentials['key_file'] = key_file
            self.cloud_credentials['project_id'] = project_id # Use the determined project ID
        else:
            logger.error("Invalid option selected")
            return False

        return True

    # --- [ MODIFIED: verify_cloud_resources becomes configure_and_create_cloud_resource ] ---
    def configure_and_create_cloud_resource(self) -> bool:
        """Verify cloud provider credentials, select target resource, and create it."""
        logger.info(f"Configuring and creating resource on {self.cloud_provider.upper()}...")

        try:
            if self.cloud_provider == 'aws':
                return self._configure_and_create_aws_resource()
            elif self.cloud_provider == 'azure':
                return self._configure_and_create_azure_resource()
            elif self.cloud_provider == 'gcp':
                return self._configure_and_create_gcp_resource()

            logger.error(f"Cloud provider {self.cloud_provider} configuration/creation not implemented.")
            return False
        except NoCredentialsError:
             logger.error(f"Could not find AWS credentials. Ensure they are configured correctly (profile, keys, or role).")
             return False
        except azure.core.exceptions.ClientAuthenticationError as e:
             logger.error(f"Azure authentication failed: {e}")
             logger.error("Hint: Check Service Principal details, CLI login status, or Managed Identity configuration.")
             return False
        except google.auth.exceptions.DefaultCredentialsError as e:
             logger.error(f"GCP Application Default Credentials not found or invalid: {e}")
             logger.error("Hint: Run 'gcloud auth application-default login' or ensure the environment provides ADC.")
             return False
        except google.auth.exceptions.RefreshError as e:
             logger.error(f"GCP credentials could not be refreshed: {e}")
             logger.error("Hint: Credentials might be expired or revoked.")
             return False
        except ClientError as e: # Catch specific boto3 errors
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == 'InvalidClientTokenId' or error_code == 'SignatureDoesNotMatch':
                 logger.error(f"AWS authentication failed: {e}")
                 logger.error("Hint: Check your AWS Access Key ID and Secret Access Key.")
            elif error_code == 'ExpiredToken':
                 logger.error(f"AWS temporary credentials have expired: {e}")
            elif error_code == 'AccessDenied':
                 logger.error(f"AWS access denied: {e}")
                 logger.error("Hint: Ensure your credentials have the necessary IAM permissions.")
            else:
                 logger.error(f"AWS API error during configuration/creation: {e}")
            return False
        except google_exceptions.PermissionDenied as e:
             logger.error(f"GCP permission denied: {e}")
             logger.error("Hint: Ensure the service account or ADC principal has the required IAM roles.")
             return False
        except google_exceptions.NotFound as e:
             logger.error(f"GCP resource not found during operation: {e}")
             return False
        except Exception as e:
            logger.error(f"Unexpected error during cloud resource configuration/creation: {e}", exc_info=True)
            return False

    # --- [ HELPER: Get Cloud Clients/Sessions ] ---
    def _get_aws_session(self) -> Optional[boto3.Session]:
        """Initializes and returns a boto3 Session based on stored credentials."""
        creds = self.cloud_credentials
        session_params = {}

        # Determine region - prefer explicit, then profile, then default
        region = creds.get('region')
        if not region and creds.get('type') == 'profile':
             # Try to get region from profile config
             try:
                  temp_session = boto3.Session(profile_name=creds.get('profile'))
                  region = temp_session.region_name
             except Exception:
                  pass # Ignore if profile doesn't exist or region isn't set

        if region:
             session_params['region_name'] = region
        elif boto3.Session().region_name: # Fallback to environment default
             session_params['region_name'] = boto3.Session().region_name
             logger.info(f"Using default AWS region: {session_params['region_name']}")
        else:
             session_params['region_name'] = 'us-east-1' # Last resort default
             logger.warning(f"AWS region not specified, defaulting to {session_params['region_name']}")

        self.cloud_credentials['region'] = session_params['region_name'] # Store the decided region back

        try:
            if creds['type'] == 'profile':
                session_params['profile_name'] = creds['profile']
                logger.info(f"Using AWS profile: {creds['profile']} in region {session_params['region_name']}")
                return boto3.Session(**session_params)
            elif creds['type'] == 'keys':
                logger.info(f"Using AWS access keys in region {session_params['region_name']}")
                session_params['aws_access_key_id'] = creds['access_key']
                session_params['aws_secret_access_key'] = creds['secret_key']
                return boto3.Session(**session_params)
            elif creds['type'] == 'assume_role':
                 logger.info(f"Attempting to assume role: {creds['role_arn']}")
                 # Create base session first
                 base_session_params = {'region_name': session_params['region_name']} # Use same region for base unless specified otherwise
                 if creds['base_type'] == 'profile':
                      base_session_params['profile_name'] = creds['base_profile']
                      base_session = boto3.Session(**base_session_params)
                 elif creds['base_type'] == 'keys':
                      base_session_params['aws_access_key_id'] = creds['base_access_key']
                      base_session_params['aws_secret_access_key'] = creds['base_secret_key']
                      base_session = boto3.Session(**base_session_params)
                 else:
                      logger.error("Invalid base credential type for assume role.")
                      return None

                 sts_client = base_session.client('sts')
                 assumed_role_object = sts_client.assume_role(
                      RoleArn=creds['role_arn'],
                      RoleSessionName=creds['session_name']
                 )
                 assumed_creds = assumed_role_object['Credentials']
                 logger.info(f"Successfully assumed role {creds['role_arn']}")

                 # Create new session with assumed credentials
                 return boto3.Session(
                      aws_access_key_id=assumed_creds['AccessKeyId'],
                      aws_secret_access_key=assumed_creds['SecretAccessKey'],
                      aws_session_token=assumed_creds['SessionToken'],
                      region_name=session_params['region_name'] # Use the originally decided region for the role session
                 )
            else:
                 logger.error(f"Unsupported AWS credential type: {creds['type']}")
                 return None
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"AWS credential error: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to create AWS session: {e}")
            return None

    def _get_azure_credential(self) -> Optional[azure.identity.ChainedTokenCredential]:
         """Gets the appropriate Azure credential object."""
         creds = self.cloud_credentials
         credential_list = []

         try:
              if creds['type'] == 'cli':
                   logger.info("Using Azure CLI credential.")
                   credential_list.append(azure.identity.AzureCliCredential())
              elif creds['type'] == 'service_principal':
                   logger.info("Using Azure Service Principal credential.")
                   credential_list.append(azure.identity.ClientSecretCredential(
                        tenant_id=creds['tenant_id'],
                        client_id=creds['client_id'],
                        client_secret=creds['client_secret']
                   ))
              elif creds['type'] == 'managed_identity':
                   msi_client_id = creds.get('msi_client_id')
                   if msi_client_id:
                        logger.info(f"Using User-Assigned Managed Identity (ClientID: {msi_client_id}).")
                        credential_list.append(azure.identity.ManagedIdentityCredential(client_id=msi_client_id))
                   else:
                        logger.info("Using System-Assigned Managed Identity.")
                        credential_list.append(azure.identity.ManagedIdentityCredential())
              else:
                   logger.error(f"Unsupported Azure credential type: {creds['type']}")
                   return None

              # Use ChainedTokenCredential to attempt the selected method
              # It might be better to return the specific credential chosen,
              # but Chained allows fallback if needed (though we don't configure fallbacks here).
              if credential_list:
                   return azure.identity.ChainedTokenCredential(*credential_list)
              else:
                   return None # Should not happen if logic is correct

         except ImportError:
              logger.error("Azure identity library not found. Please install 'azure-identity'.")
              return None
         except Exception as e:
              logger.error(f"Failed to create Azure credential object: {e}")
              return None

    def _get_gcp_credential(self) -> Optional[Tuple[object, str]]:
         """Gets GCP credentials object and project ID."""
         creds = self.cloud_credentials
         project_id = creds.get('project_id')

         if not project_id:
              logger.error("GCP Project ID is missing.")
              return None, None

         try:
              if creds['type'] == 'application_default':
                   logger.info(f"Using GCP Application Default Credentials for project {project_id}.")
                   # ADC automatically finds credentials, return None for cred object, rely on SDK finding them
                   credentials, discovered_project_id = google.auth.default()
                   if discovered_project_id and discovered_project_id != project_id:
                        logger.warning(f"ADC discovered project '{discovered_project_id}', but using configured project '{project_id}'.")
                        # Force the project_id we stored
                        credentials = credentials.with_quota_project(project_id)
                   elif not discovered_project_id and project_id:
                        logger.info(f"Setting quota project ID to '{project_id}' for ADC.")
                        credentials = credentials.with_quota_project(project_id)

                   return credentials, project_id
              elif creds['type'] == 'service_account':
                   key_file = creds['key_file']
                   logger.info(f"Using GCP Service Account key file: {key_file} for project {project_id}.")
                   credentials = service_account.Credentials.from_service_account_file(key_file)
                   # Ensure the project ID is associated if needed (some clients require it explicitly)
                   credentials = credentials.with_quota_project(project_id)
                   return credentials, project_id
              else:
                   logger.error(f"Unsupported GCP credential type: {creds['type']}")
                   return None, None
         except (google.auth.exceptions.DefaultCredentialsError, google.auth.exceptions.RefreshError, FileNotFoundError) as e:
              logger.error(f"GCP credential error: {e}")
              return None, None
         except Exception as e:
              logger.error(f"Failed to create GCP credentials: {e}")
              return None, None


    # --- [ AWS: Configure and Create Logic ] ---
    def _configure_and_create_aws_resource(self) -> bool:
        """Configure AWS deployment target and create the resource."""
        session = self._get_aws_session()
        if not session:
             return False
        region = self.cloud_credentials['region'] # Get the decided region
        logger.info(f"Verifying AWS resources in region: {region}...")

        # Clients needed for verification/creation
        ec2 = session.client('ec2')
        ecs = session.client('ecs')
        lambda_client = session.client('lambda') # Keep client names consistent

        # --- Resource Selection (similar to original verify) ---
        print("\nAvailable AWS deployment targets:")
        print("1. EC2 (Virtual Machine - Creates Instance + Key Pair + Security Group)") # Clarify creation
        print("2. ECS/Fargate (Containers - Requires existing cluster or creates one)")
        print("3. Lambda (Serverless - Creates basic function placeholder)")

        choice = input("Select deployment target (1-3): ")

        if choice == '1':
            self.resource_configuration['type'] = 'ec2'
            instance_types = ['t2.micro', 't2.small', 't3.micro', 't3.small', 'm5.large'] # Updated list
            print("\nSelect EC2 instance type:")
            for i, instance_type in enumerate(instance_types, 1):
                print(f"{i}. {instance_type}")

            instance_choice = input(f"Instance type (1-{len(instance_types)}) [default: {instance_types[0]}]: ")
            try:
                idx = int(instance_choice) - 1
                if 0 <= idx < len(instance_types):
                    self.resource_configuration['instance_type'] = instance_types[idx]
                else:
                    self.resource_configuration['instance_type'] = instance_types[0]
            except ValueError:
                self.resource_configuration['instance_type'] = instance_types[0]
            logger.info(f"Selected instance type: {self.resource_configuration['instance_type']}")

            # --- EC2 Creation Step ---
            return self._create_aws_ec2_instance(ec2)

        elif choice == '2':
            self.resource_configuration['type'] = 'ecs'
            # Simplified: Always create a new cluster for this example
            cluster_name = input("Enter name for NEW ECS cluster [ai-devops-cluster]: ") or "ai-devops-cluster"
            self.resource_configuration['cluster_name'] = cluster_name
            self.resource_configuration['create_cluster'] = True # Flag to create

             # --- ECS Cluster Creation Step ---
            return self._create_aws_ecs_cluster(ecs)


        elif choice == '3':
            self.resource_configuration['type'] = 'lambda'
            self.resource_configuration['function_name'] = input("Enter Lambda function name [ai-devops-function]: ") or "ai-devops-function"
            memory_values = [128, 256, 512, 1024]
            print("\nSelect Lambda memory allocation (MB):")
            for i, memory in enumerate(memory_values, 1):
                print(f"{i}. {memory}")

            memory_choice = input(f"Memory allocation (1-{len(memory_values)}) [default: {memory_values[0]}]: ")
            try:
                idx = int(memory_choice) - 1
                self.resource_configuration['memory'] = memory_values[idx] if 0 <= idx < len(memory_values) else memory_values[0]
            except ValueError:
                self.resource_configuration['memory'] = memory_values[0]
            logger.info(f"Selected memory: {self.resource_configuration['memory']} MB")

            # --- Lambda Function Creation Step ---
            return self._create_aws_lambda_function(lambda_client, session.client('iam')) # Need IAM client too

        else:
            logger.error("Invalid deployment target selected")
            return False

    def _create_aws_ec2_instance(self, ec2_client) -> bool:
        """Creates an EC2 instance, KeyPair, and Security Group."""
        instance_type = self.resource_configuration['instance_type']
        key_name_base = "ai-devops-ec2-key" # Base name for keys
        sg_name = "ai-devops-ec2-sg"
        region = self.cloud_credentials['region']

        logger.info(f"Creating EC2 instance ({instance_type}) in {region}...")

        try:
            # 1. Ensure Local SSH Key Pair Exists (Generate/Regenerate if needed)
            private_key_path, public_key_material, key_pair_name_base = generate_ssh_key_pair(key_name_base)
            if not private_key_path or not public_key_material:
                 logger.error("Failed to ensure local SSH key pair integrity.")
                 return False
            self.ssh_key_paths['private'] = private_key_path
            self.ssh_key_paths['public'] = f"{private_key_path}.pub" # Convention
            # key_pair_name_base is the local base name ('ai-devops-ec2-key')

            # 2. Check/Create AWS Key Pair
            key_pair_name_aws = None # This will store the name AWS uses
            try:
                 # Check if key exists on AWS using the base name
                 ec2_client.describe_key_pairs(KeyNames=[key_pair_name_base])
                 logger.info(f"Using existing AWS key pair named: {key_pair_name_base}")
                 key_pair_name_aws = key_pair_name_base
                 # Store the AWS key name for instructions etc.
                 self.ssh_key_paths['key_name'] = key_pair_name_aws
                 # Instructions need to remind user to use the local private key
                 logger.info(f"Ensure you have the corresponding private key: {self.ssh_key_paths['private']}")

            except ClientError as e:
                 if e.response['Error']['Code'] == 'InvalidKeyPair.NotFound':
                      logger.info(f"AWS key pair '{key_pair_name_base}' not found. Importing local public key...")
                      # Import the local public key into AWS
                      try:
                           key_pair = ec2_client.import_key_pair(
                                KeyName=key_pair_name_base, # Use the base name for AWS key
                                PublicKeyMaterial=public_key_material.encode('utf-8') # import_key_pair expects bytes
                           )
                           key_pair_name_aws = key_pair['KeyName']
                           self.ssh_key_paths['key_name'] = key_pair_name_aws # Store the name AWS uses
                           logger.info(f"Successfully created and imported key pair to AWS: {key_pair_name_aws}")
                      except ClientError as import_e:
                           logger.error(f"Failed to import public key to AWS: {import_e}")
                           return False
                      except Exception as import_e: # Catch potential encoding errors too
                           logger.error(f"Unexpected error importing public key to AWS: {import_e}")
                           return False

                 else:
                      logger.error(f"Error checking AWS key pair: {e}")
                      raise # Re-raise other unexpected errors

            if not key_pair_name_aws: # Should have a name by now if successful
                 logger.error("Failed to obtain a valid AWS SSH key pair name.")
                 return False


            # 3. Create/Get Security Group (No change needed here)
            sg_id = None
            try:
                # ... (rest of SG logic remains the same) ...
                 response = ec2_client.describe_security_groups(GroupNames=[sg_name])
                 sg_id = response['SecurityGroups'][0]['GroupId']
                 logger.info(f"Using existing security group: {sg_name} ({sg_id})")
            except ClientError as e:
                 if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
                     # ... (SG creation logic remains the same) ...
                     logger.info(f"Security group '{sg_name}' not found. Creating new one...")
                     vpc_id = None
                     try:
                          # Find default VPC
                          vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
                          if vpcs['Vpcs']:
                               vpc_id = vpcs['Vpcs'][0]['VpcId']
                          else: # No default VPC, need to handle this (e.g., error out or create VPC)
                               logger.error("No default VPC found in this region. Cannot create security group automatically.")
                               return False
                     except ClientError as vpc_e:
                          logger.error(f"Error finding default VPC: {vpc_e}")
                          return False

                     sg = ec2_client.create_security_group(
                         GroupName=sg_name,
                         Description='Security group for AI DevOps EC2 instance',
                         VpcId=vpc_id
                     )
                     sg_id = sg['GroupId']
                     logger.info(f"Created security group: {sg_name} ({sg_id})")

                     # Allow SSH and potentially HTTP/HTTPS
                     ec2_client.authorize_security_group_ingress(
                         GroupId=sg_id,
                         IpPermissions=[
                             {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Allow SSH access'}]},
                             {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Allow HTTP access'}]},
                             {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Allow HTTPS access'}]},
                         ]
                     )
                     logger.info(f"Authorized SSH (22), HTTP (80), HTTPS (443) ingress for {sg_name}")

                 else:
                     raise # Re-raise other errors

            if not sg_id:
                  logger.error("Failed to obtain a valid Security Group ID.")
                  return False

            # 4. Get Latest Amazon Linux 2 AMI (No change needed here)
            # ... (AMI logic remains the same) ...
            
            # ... (rest of AMI finding logic) ...
            # Retrieve the latest Amazon Linux 2 AMI
            logger.info("Finding latest Amazon Linux 2 AMI...")
            images = ec2_client.describe_images(
                Filters=[
                    {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                    {'Name': 'state', 'Values': ['available']}
                ],
                Owners=['amazon']
            )
            sorted_images = sorted(images['Images'], key=lambda x: x['CreationDate'], reverse=True)
            if not sorted_images:
                logger.error("No suitable AMI found for Amazon Linux 2.")
                return False
            ami_id = sorted_images[0]['ImageId']
            logger.info(f"Using AMI ID: {ami_id}")


            # 5. Launch Instance (Use key_pair_name_aws)
            logger.info(f"Launching EC2 instance {instance_type} using AMI {ami_id}, Key {key_pair_name_aws}, SG {sg_id}...") # Use AWS key name
            run_response = ec2_client.run_instances(
                ImageId=ami_id,
                InstanceType=instance_type,
                KeyName=key_pair_name_aws, # Use the name known to AWS
                SecurityGroupIds=[sg_id],
                MinCount=1,
                MaxCount=1,
                TagSpecifications=[ # Add tags for identification
                     { # ... (tags remain the same) ...
                          'ResourceType': 'instance',
                          'Tags': [
                               {'Key': 'Name', 'Value': 'ai-devops-instance'},
                               {'Key': 'CreatedBy', 'Value': 'ai-devops-tool'},
                          ]
                     },
                ]
            )

            instance_id = run_response['Instances'][0]['InstanceId']
            logger.info(f"Instance requested: {instance_id}. Waiting for it to run...")

            # Wait for the instance to be in 'running' state
            waiter = ec2_client.get_waiter('instance_running')
            waiter.wait(InstanceIds=[instance_id])
            logger.info(f"Instance {instance_id} is now running.")

            # 5. Get Instance Details (Public IP/DNS)
            desc_response = ec2_client.describe_instances(InstanceIds=[instance_id])
            instance_info = desc_response['Reservations'][0]['Instances'][0]
            public_ip = instance_info.get('PublicIpAddress')
            public_dns = instance_info.get('PublicDnsName')

            # Store details
            self.created_resource_details = {
                'type': 'AWS EC2 Instance',
                'id': instance_id,
                'region': region,
                'instance_type': instance_type,
                'ami_id': ami_id,
                'key_pair_name': key_pair_name_aws,
                'security_group_id': sg_id,
                'security_group_name': sg_name,
                'public_ip': public_ip,
                'public_dns': public_dns,
                'ssh_user': 'ec2-user', # Default for Amazon Linux
                'ssh_key_private_path': self.ssh_key_paths.get('private', 'N/A')
            }
            logger.info(f"EC2 Instance Created Successfully:")
            logger.info(f"  ID: {instance_id}")
            logger.info(f"  Public IP: {public_ip}")
            logger.info(f"  Public DNS: {public_dns}")
            logger.info(f"  SSH Key: {self.ssh_key_paths.get('private')}")
            logger.info(f"  SSH User: {self.created_resource_details['ssh_user']}")

            return True

        except ClientError as e:
            logger.error(f"AWS API error during EC2 instance creation: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during EC2 instance creation: {e}", exc_info=True)
            return False

    def _create_aws_ecs_cluster(self, ecs_client) -> bool:
        """Creates a basic ECS cluster."""
        cluster_name = self.resource_configuration['cluster_name']
        logger.info(f"Creating ECS cluster: {cluster_name}...")
        try:
            response = ecs_client.create_cluster(clusterName=cluster_name)
            cluster_arn = response['cluster']['clusterArn']
            self.created_resource_details = {
                'type': 'AWS ECS Cluster',
                'name': cluster_name,
                'arn': cluster_arn,
                'region': self.cloud_credentials['region']
            }
            logger.info(f"ECS Cluster created successfully: {cluster_arn}")
            # Note: This only creates the cluster. Services/Task Definitions are needed for deployment.
            # The CI/CD pipeline would handle service creation/updates.
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidParameterException' and 'already exists' in str(e):
                 logger.warning(f"ECS Cluster '{cluster_name}' already exists. Proceeding.")
                 # Optionally fetch the existing cluster ARN here
                 try:
                     desc_response = ecs_client.describe_clusters(clusters=[cluster_name])
                     if desc_response['clusters']:
                          cluster_arn = desc_response['clusters'][0]['clusterArn']
                          self.created_resource_details = {
                               'type': 'AWS ECS Cluster (Existing)',
                               'name': cluster_name,
                               'arn': cluster_arn,
                               'region': self.cloud_credentials['region']
                          }
                          return True
                     else:
                          logger.error(f"Cluster '{cluster_name}' reported as existing but could not be described.")
                          return False
                 except ClientError as desc_e:
                      logger.error(f"Error describing existing cluster '{cluster_name}': {desc_e}")
                      return False

            logger.error(f"AWS API error during ECS cluster creation: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during ECS cluster creation: {e}", exc_info=True)
            return False

    def _create_aws_lambda_function(self, lambda_client, iam_client) -> bool:
        """Creates a placeholder Lambda function with a basic execution role."""
        function_name = self.resource_configuration['function_name']
        memory = self.resource_configuration['memory']
        region = self.cloud_credentials['region']
        role_name = f"{function_name}-execution-role"
        policy_name = f"{role_name}-policy"
        runtime = 'python3.9' # Default, adjust based on detected_stack if needed

        logger.info(f"Creating Lambda function '{function_name}' ({runtime}, {memory}MB) in {region}...")

        # Adjust runtime based on detected stack
        if self.detected_stack == 'nodejs':
             runtime = 'nodejs16.x' # Or a more current version
        elif self.detected_stack == 'python':
             runtime = 'python3.9' # Or a more current version
        elif self.detected_stack == 'java':
             runtime = 'java11' # Or a more current version
        elif self.detected_stack == 'golang':
             runtime = 'go1.x'
        elif self.detected_stack == 'dotnet':
             runtime = 'dotnet6' # Or a more current version
        # Add others as needed

        logger.info(f"Using runtime: {runtime}")

        try:
            # 1. Create/Get IAM Execution Role
            role_arn = None
            assume_role_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
            try:
                response = iam_client.get_role(RoleName=role_name)
                role_arn = response['Role']['Arn']
                logger.info(f"Using existing IAM role: {role_name} ({role_arn})")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    logger.info(f"IAM role '{role_name}' not found. Creating new one...")
                    role_response = iam_client.create_role(
                        RoleName=role_name,
                        AssumeRolePolicyDocument=json.dumps(assume_role_policy),
                        Description=f"Execution role for Lambda function {function_name}"
                    )
                    role_arn = role_response['Role']['Arn']
                    logger.info(f"Created IAM role: {role_name} ({role_arn})")

                    # Attach basic execution policy (CloudWatch Logs)
                    policy_arn = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
                    logger.info(f"Attaching policy {policy_arn} to role {role_name}...")
                    iam_client.attach_role_policy(
                        RoleName=role_name,
                        PolicyArn=policy_arn
                    )
                    # Wait a bit for IAM propagation
                    import time
                    time.sleep(10)
                    logger.info("Policy attached.")
                else:
                    raise # Re-raise other errors

            if not role_arn:
                 logger.error("Failed to get or create IAM role for Lambda.")
                 return False

            # 2. Create Dummy Code Package (required for creation)
            # Create a simple placeholder file
            dummy_file_content = ""
            handler_name = "lambda_function.lambda_handler" # Python default
            if runtime.startswith('nodejs'):
                 dummy_file_content = "exports.handler = async (event) => { console.log('Hello from AI DevOps Lambda!'); return { statusCode: 200, body: 'OK' }; };"
                 handler_name = "index.handler"
                 dummy_filename = "index.js"
            elif runtime.startswith('python'):
                 dummy_file_content = "import json\ndef lambda_handler(event, context):\n    print('Hello from AI DevOps Lambda!')\n    return {'statusCode': 200,'body': json.dumps('OK')}"
                 handler_name = "lambda_function.lambda_handler"
                 dummy_filename = "lambda_function.py"
            # Add other runtimes if needed

            if not dummy_file_content:
                 logger.error(f"Cannot create dummy code for runtime {runtime}. Lambda creation skipped.")
                 return False # Cannot create without code

            zip_file_path = os.path.join(tempfile.gettempdir(), f"{function_name}_dummy_code.zip")
            dummy_file_path = os.path.join(tempfile.gettempdir(), dummy_filename)

            with open(dummy_file_path, 'w') as f:
                 f.write(dummy_file_content)

            import zipfile
            with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                 zf.write(dummy_file_path, arcname=dummy_filename) # Add file to zip at root

            logger.info(f"Created dummy code package: {zip_file_path}")

            # Read zip file content
            with open(zip_file_path, 'rb') as f:
                 zip_content = f.read()

            # 3. Create Lambda Function
            logger.info(f"Creating function {function_name}...")
            create_response = lambda_client.create_function(
                FunctionName=function_name,
                Runtime=runtime,
                Role=role_arn,
                Handler=handler_name,
                Code={'ZipFile': zip_content},
                Description='Lambda function created by AI DevOps Automator',
                Timeout=30, # Default timeout
                MemorySize=memory,
                Publish=True # Publish version 1
            )

            function_arn = create_response['FunctionArn']
            logger.info(f"Lambda function created successfully: {function_arn}")

            self.created_resource_details = {
                'type': 'AWS Lambda Function',
                'name': function_name,
                'arn': function_arn,
                'runtime': runtime,
                'memory': memory,
                'role_arn': role_arn,
                'region': region
            }

             # Clean up dummy files
            try:
                 os.remove(dummy_file_path)
                 os.remove(zip_file_path)
            except OSError as e:
                 logger.warning(f"Could not clean up temporary Lambda code files: {e}")

            return True

        except ClientError as e:
             if e.response['Error']['Code'] == 'ResourceConflictException':
                  logger.warning(f"Lambda function '{function_name}' already exists. Skipping creation.")
                  # Try to get existing function details
                  try:
                       get_response = lambda_client.get_function(FunctionName=function_name)
                       config = get_response['Configuration']
                       self.created_resource_details = {
                            'type': 'AWS Lambda Function (Existing)',
                            'name': config['FunctionName'],
                            'arn': config['FunctionArn'],
                            'runtime': config['Runtime'],
                            'memory': config['MemorySize'],
                            'role_arn': config['Role'],
                            'region': region
                       }
                       return True
                  except ClientError as get_e:
                       logger.error(f"Function reported as existing but failed to get details: {get_e}")
                       return False
             elif e.response['Error']['Code'] == 'InvalidParameterValueException' and 'role' in str(e).lower():
                  logger.error(f"IAM Role ({role_name}/{role_arn}) is not ready or has incorrect permissions: {e}")
                  logger.error("Hint: IAM changes can take time to propagate. Try again in a minute.")
                  return False
             else:
                  logger.error(f"AWS API error during Lambda function creation: {e}")
                  return False
        except Exception as e:
             logger.error(f"Unexpected error during Lambda function creation: {e}", exc_info=True)
             # Clean up dummy files even on failure
             try:
                  if 'dummy_file_path' in locals() and os.path.exists(dummy_file_path): os.remove(dummy_file_path)
                  if 'zip_file_path' in locals() and os.path.exists(zip_file_path): os.remove(zip_file_path)
             except OSError as clean_e:
                  logger.warning(f"Could not clean up temporary Lambda code files on error: {clean_e}")
             return False


    # --- [ Azure: Configure and Create Logic ] ---
    def _configure_and_create_azure_resource(self) -> bool:
        """Configure Azure deployment target and create the resource."""
        credential = self._get_azure_credential()
        subscription_id = self.cloud_credentials.get('subscription_id')

        if not credential or not subscription_id:
            logger.error("Azure credentials or subscription ID missing.")
            return False

        logger.info(f"Verifying Azure resources for subscription: {subscription_id}...")

        # Clients needed
        resource_client = azure.mgmt.resource.ResourceManagementClient(credential, subscription_id)
        compute_client = azure.mgmt.compute.ComputeManagementClient(credential, subscription_id)
        network_client = azure.mgmt.network.NetworkManagementClient(credential, subscription_id)
        # web_client = azure.mgmt.web.WebSiteManagementClient(credential, subscription_id) # If needed for AppService/Functions

        # Resource Group Selection/Creation
        try:
            logger.info("Listing available Azure resource groups...")
            resource_groups = list(resource_client.resource_groups.list()) # Materialize the iterator

            if resource_groups:
                 print("\nAvailable Azure resource groups:")
                 for i, group in enumerate(resource_groups, 1):
                      print(f"{i}. {group.name} (Location: {group.location})")
            else:
                 print("\nNo existing resource groups found in this subscription.")

            group_choice = input("Select resource group by number, or enter 'new' to create one: ")

            if group_choice.lower() == 'new':
                group_name = input("Enter NEW resource group name: ")
                # List common locations
                common_locations = ['eastus', 'westus2', 'westeurope', 'southeastasia', 'centralus']
                location = input(f"Enter location (e.g., {', '.join(common_locations)}) [eastus]: ") or "eastus"

                if not group_name:
                     logger.error("New resource group name cannot be empty.")
                     return False

                logger.info(f"Creating resource group '{group_name}' in location '{location}'...")
                rg_result = resource_client.resource_groups.create_or_update(
                    group_name,
                    {'location': location}
                )
                logger.info(f"Resource group '{rg_result.name}' created/updated successfully.")
                self.resource_configuration['resource_group'] = rg_result.name
                self.resource_configuration['location'] = rg_result.location
            else:
                try:
                    idx = int(group_choice) - 1
                    if 0 <= idx < len(resource_groups):
                        group = resource_groups[idx]
                        self.resource_configuration['resource_group'] = group.name
                        self.resource_configuration['location'] = group.location
                        logger.info(f"Selected resource group: {group.name} in {group.location}")
                    else:
                        logger.error("Invalid resource group selection number.")
                        return False
                except ValueError:
                    logger.error("Invalid input, please enter a number or 'new'.")
                    return False
                except IndexError:
                     logger.error("Invalid selection number.") # Should be caught by the index check, but good practice
                     return False

        except Exception as e:
            logger.error(f"Error listing or creating Azure resource group: {e}", exc_info=True)
            return False

        # --- Deployment Target Selection ---
        print("\nAvailable Azure deployment targets:")
        print("1. Azure VM (Virtual Machine - Creates VM + Network + Key)") # Clarify
        print("2. App Service (Web App - Placeholder, requires separate setup)") # Keep simple for now
        # Add other options like ACI, Functions later if needed

        choice = input("Select deployment target (1-2): ")

        if choice == '1':
            self.resource_configuration['type'] = 'vm'
            vm_sizes = ['Standard_B1s', 'Standard_B2s', 'Standard_D2s_v3', 'Standard_F2s_v2']
            print("\nSelect VM size:")
            for i, size in enumerate(vm_sizes, 1):
                print(f"{i}. {size}")

            vm_choice = input(f"VM size (1-{len(vm_sizes)}) [default: {vm_sizes[0]}]: ")
            try:
                idx = int(vm_choice) - 1
                self.resource_configuration['vm_size'] = vm_sizes[idx] if 0 <= idx < len(vm_sizes) else vm_sizes[0]
            except ValueError:
                self.resource_configuration['vm_size'] = vm_sizes[0]
            logger.info(f"Selected VM size: {self.resource_configuration['vm_size']}")

            vm_name = input("Enter VM name [ai-devops-vm]: ") or "ai-devops-vm"
            self.resource_configuration['vm_name'] = vm_name
            admin_user = input("Enter admin username for VM [azureuser]: ") or "azureuser"
            self.resource_configuration['admin_username'] = admin_user

            # --- Azure VM Creation Step ---
            return self._create_azure_vm(compute_client, network_client, resource_client)

        elif choice == '2':
             # Simplified App Service Placeholder (requires more setup for real deployment)
            self.resource_configuration['type'] = 'app_service'
            app_name = input("Enter App Service name [ai-devops-webapp]: ") or "ai-devops-webapp"
            # App names must be globally unique
            logger.warning(f"App Service name '{app_name}' must be globally unique across Azure.")
            self.resource_configuration['app_name'] = app_name

            # Placeholder - real creation is complex (needs Plan first)
            logger.info("App Service creation is complex; this tool will only configure the name.")
            logger.info("You will need to create the App Service Plan and App Service manually or enhance this script.")
            self.created_resource_details = {
                'type': 'Azure App Service (Placeholder)',
                'name': app_name,
                'resource_group': self.resource_configuration['resource_group'],
                'location': self.resource_configuration['location'],
                'status': 'Configuration stored, requires manual creation or script enhancement.'
            }
            return True # Return true as configuration is stored, even if resource not created

        else:
            logger.error("Invalid deployment target selected")
            return False


    def _create_azure_vm(self, compute_client, network_client, resource_client) -> bool:
         """Creates an Azure VM with basic networking."""
         rg_name = self.resource_configuration['resource_group']
         location = self.resource_configuration['location']
         vm_name = self.resource_configuration['vm_name']
         vm_size = self.resource_configuration['vm_size']
         admin_username = self.resource_configuration['admin_username']
         key_name_base = f"ai-devops-{vm_name}-key"

         logger.info(f"Creating Azure VM '{vm_name}' ({vm_size}) in {rg_name} ({location})...")

         try:
              # 1. Generate SSH Key Pair locally
              private_key_path, public_key_content, _ = generate_ssh_key_pair(key_name_base)
              if not private_key_path:
                   logger.error("Failed to generate local SSH key pair for Azure VM.")
                   return False
              self.ssh_key_paths['private'] = private_key_path
              self.ssh_key_paths['public'] = f"{private_key_path}.pub" # Store public path too

              # 2. Create Virtual Network (or use existing default)
              vnet_name = f"{vm_name}-vnet"
              subnet_name = "default"
              logger.info(f"Checking/Creating Virtual Network '{vnet_name}'...")
              vnet_poller = network_client.virtual_networks.begin_create_or_update(
                   rg_name,
                   vnet_name,
                   {
                        "location": location,
                        "address_space": {"address_prefixes": ["10.0.0.0/16"]}
                   }
              )
              vnet_result = vnet_poller.result()
              logger.info(f"VNet '{vnet_result.name}' available.")

              # 3. Create Subnet
              logger.info(f"Checking/Creating Subnet '{subnet_name}' in VNet '{vnet_name}'...")
              subnet_poller = network_client.subnets.begin_create_or_update(
                   rg_name,
                   vnet_name,
                   subnet_name,
                   {"address_prefix": "10.0.0.0/24"}
              )
              subnet_result = subnet_poller.result()
              logger.info(f"Subnet '{subnet_result.name}' available.")

              # 4. Create Public IP Address
              public_ip_name = f"{vm_name}-pip"
              logger.info(f"Checking/Creating Public IP Address '{public_ip_name}'...")
              pip_poller = network_client.public_ip_addresses.begin_create_or_update(
                   rg_name,
                   public_ip_name,
                   {
                        "location": location,
                        "sku": {"name": "Standard"}, # Standard SKU recommended
                        "public_ip_allocation_method": "Static" # Or Dynamic
                   }
              )
              pip_result = pip_poller.result()
              logger.info(f"Public IP Address '{pip_result.name}' available ({pip_result.ip_address}).")

              # 5. Create Network Interface (NIC)
              nic_name = f"{vm_name}-nic"
              logger.info(f"Checking/Creating Network Interface '{nic_name}'...")
              nic_poller = network_client.network_interfaces.begin_create_or_update(
                   rg_name,
                   nic_name,
                   {
                        "location": location,
                        "ip_configurations": [{
                             "name": "ipconfig1",
                             "subnet": {"id": subnet_result.id},
                             "public_ip_address": {"id": pip_result.id}
                        }]
                   }
              )
              nic_result = nic_poller.result()
              logger.info(f"Network Interface '{nic_result.name}' available.")

              # 6. Define VM Configuration
              logger.info(f"Defining VM configuration for '{vm_name}'...")
              vm_parameters = {
                   "location": location,
                   "properties": {
                        "hardwareProfile": {"vmSize": vm_size},
                        "storageProfile": {
                             "imageReference": {
                                  # Using Ubuntu LTS image
                                  "publisher": "Canonical",
                                  "offer": "UbuntuServer",
                                  "sku": "18.04-LTS", # Or "20.04-LTS", "22.04-LTS"
                                  "version": "latest"
                             },
                             "osDisk": {
                                  "createOption": "FromImage",
                                  "managedDisk": {
                                       "storageAccountType": "Standard_LRS" # Or Premium_LRS
                                  }
                             }
                        },
                        "osProfile": {
                             "computerName": vm_name,
                             "adminUsername": admin_username,
                             "linuxConfiguration": {
                                  "disablePasswordAuthentication": True,
                                  "ssh": {
                                       "publicKeys": [{
                                            "path": f"/home/{admin_username}/.ssh/authorized_keys",
                                            "keyData": public_key_content
                                       }]
                                  }
                             }
                        },
                        "networkProfile": {
                             "networkInterfaces": [{
                                  "id": nic_result.id,
                                  "properties": {"primary": True}
                             }]
                        }
                   },
                   "name": vm_name
              }

              # 7. Create Virtual Machine
              logger.info(f"Submitting VM creation request for '{vm_name}' (this may take a few minutes)...")
              vm_poller = compute_client.virtual_machines.begin_create_or_update(
                   rg_name,
                   vm_name,
                   vm_parameters
              )
              vm_result = vm_poller.result()
              logger.info(f"Azure VM '{vm_result.name}' created successfully.")

              # 8. Get VM Details (including the potentially updated Public IP)
              vm_details = compute_client.virtual_machines.get(rg_name, vm_name, expand='instanceView')
              # Need to get the updated IP address after creation/start
              pip_details = network_client.public_ip_addresses.get(rg_name, public_ip_name)
              public_ip_address = pip_details.ip_address

              self.created_resource_details = {
                   'type': 'Azure VM',
                   'name': vm_result.name,
                   'id': vm_result.id,
                   'resource_group': rg_name,
                   'location': location,
                   'size': vm_size,
                   'public_ip': public_ip_address,
                   'admin_username': admin_username,
                   'ssh_key_private_path': self.ssh_key_paths.get('private')
              }
              logger.info("Azure VM Created Successfully:")
              logger.info(f"  Name: {vm_result.name}")
              logger.info(f"  Public IP: {public_ip_address}")
              logger.info(f"  Admin User: {admin_username}")
              logger.info(f"  SSH Key: {self.ssh_key_paths.get('private')}")

              # 9. (Optional but recommended) Add NSG rule for SSH
              nsg_name = nic_result.network_security_group.id.split('/')[-1] if nic_result.network_security_group else f"{vm_name}-nsg" # Default NSG might be created
              try:
                   logger.info(f"Attempting to add SSH rule to NSG associated with NIC or a default NSG '{nsg_name}'...")
                   # Check if NSG exists before creating/updating rule
                   try:
                        network_client.network_security_groups.get(rg_name, nsg_name)
                   except azure.core.exceptions.ResourceNotFoundError:
                        logger.info(f"NSG '{nsg_name}' not found. Creating one.")
                        nsg_poller = network_client.network_security_groups.begin_create_or_update(
                             rg_name, nsg_name, {"location": location}
                        )
                        nsg_result = nsg_poller.result()
                        logger.info(f"Created NSG '{nsg_result.name}'. Associating with NIC.")
                        # Associate NSG with NIC
                        nic_result.network_security_group = nsg_result
                        nic_update_poller = network_client.network_interfaces.begin_create_or_update(rg_name, nic_name, nic_result)
                        nic_update_poller.result()


                   rule_poller = network_client.security_rules.begin_create_or_update(
                        rg_name, nsg_name, "AllowSSH",
                        {
                             "protocol": "Tcp",
                             "source_address_prefix": "*",
                             "destination_address_prefix": "*",
                             "access": "Allow",
                             "direction": "Inbound",
                             "source_port_range": "*",
                             "destination_port_range": "22",
                             "priority": 100, # Lower number = higher priority
                             "description": "Allow SSH access"
                        }
                   )
                   rule_result = rule_poller.result()
                   logger.info(f"Security rule '{rule_result.name}' added to NSG '{nsg_name}'.")
              except Exception as nsg_e:
                   logger.warning(f"Could not automatically add SSH rule to NSG: {nsg_e}. Please configure manually if needed.")


              return True

         except azure.core.exceptions.HttpResponseError as e:
              logger.error(f"Azure API error during VM creation: {e.message}", exc_info=False) # message often has useful info
              # Log more details if needed, e.g., e.response.text
              return False
         except Exception as e:
              logger.error(f"Unexpected error during Azure VM creation: {e}", exc_info=True)
              return False


    # --- [ GCP: Configure and Create Logic ] ---
    def _configure_and_create_gcp_resource(self) -> bool:
        """Configure GCP deployment target and create the resource."""
        credentials, project_id = self._get_gcp_credential()
        if not credentials or not project_id:
            return False

        logger.info(f"Verifying GCP resources for project: {project_id}...")

        # Clients needed
        compute_client = compute_v1.InstancesClient(credentials=credentials)
        # run_client = run_v1.ServicesClient(credentials=credentials) # For Cloud Run
        # functions_client = functions_v1.FunctionServiceClient(credentials=credentials) # For Cloud Functions

        # --- Deployment Target Selection ---
        print("\nAvailable GCP deployment targets:")
        print("1. Compute Engine (VM - Creates Instance + Firewall Rule + Key)") # Clarify
        print("2. Cloud Run (Serverless Containers - Placeholder, requires container image)") # Keep simple
        # Add GKE, Cloud Functions later

        choice = input("Select deployment target (1-2): ")

        if choice == '1':
            self.resource_configuration['type'] = 'vm'
            machine_types = ['e2-micro', 'e2-small', 'e2-medium', 'n1-standard-1']
            print("\nSelect machine type:")
            for i, mtype in enumerate(machine_types, 1):
                print(f"{i}. {mtype}")

            mchoice = input(f"Machine type (1-{len(machine_types)}) [default: {machine_types[0]}]: ")
            try:
                idx = int(mchoice) - 1
                self.resource_configuration['machine_type'] = machine_types[idx] if 0 <= idx < len(machine_types) else machine_types[0]
            except ValueError:
                self.resource_configuration['machine_type'] = machine_types[0]
            logger.info(f"Selected machine type: {self.resource_configuration['machine_type']}")

            zone = input("Enter zone (e.g., us-central1-a): ") or "us-central1-a"
            self.resource_configuration['zone'] = zone
            instance_name = input("Enter instance name [ai-devops-instance]: ") or "ai-devops-instance"
            self.resource_configuration['instance_name'] = instance_name

            # --- GCP VM Creation Step ---
            return self._create_gcp_vm(compute_client, credentials, project_id)

        elif choice == '2':
            # Simplified Cloud Run Placeholder
            self.resource_configuration['type'] = 'cloud_run'
            service_name = input("Enter Cloud Run service name [ai-devops-service]: ") or "ai-devops-service"
            region = input("Enter region (e.g., us-central1): ") or "us-central1"
            self.resource_configuration['service_name'] = service_name
            self.resource_configuration['region'] = region

            logger.info("Cloud Run creation requires a container image.")
            logger.info("This tool will only configure the name and region.")
            logger.info("The CI/CD pipeline should build and push the image, then deploy to Cloud Run.")
            self.created_resource_details = {
                'type': 'GCP Cloud Run (Placeholder)',
                'name': service_name,
                'region': region,
                'project_id': project_id,
                'status': 'Configuration stored, requires image build and deployment via CI/CD.'
            }
            return True

        else:
            logger.error("Invalid deployment target selected")
            return False

    def _create_gcp_vm(self, compute_client: compute_v1.InstancesClient, credentials, project_id: str) -> bool:
        """Creates a GCP Compute Engine VM instance."""
        instance_name = self.resource_configuration['instance_name']
        zone = self.resource_configuration['zone']
        machine_type = self.resource_configuration['machine_type']
        key_name_base = f"ai-devops-{instance_name}-key"
        # Standard user for Debian/Ubuntu images on GCP often differs, but 'gcpuser' is a common custom choice
        ssh_user = "gcpuser" # We'll create this user

        logger.info(f"Creating GCP Compute Engine instance '{instance_name}' ({machine_type}) in {zone}...")

        try:
            # 1. Generate SSH Key Pair locally
            private_key_path, public_key_content, _ = generate_ssh_key_pair(key_name_base)
            if not private_key_path:
                logger.error("Failed to generate local SSH key pair for GCP VM.")
                return False
            self.ssh_key_paths['private'] = private_key_path
            self.ssh_key_paths['public'] = f"{private_key_path}.pub"

            # Format public key for GCP metadata (user:key format)
            ssh_key_metadata = f"{ssh_user}:{public_key_content}"

            # 2. Get latest Debian image (common default)
            image_client = compute_v1.ImagesClient(credentials=credentials)
            latest_image = image_client.get_from_family(project="debian-cloud", family="debian-11") # Or debian-10, etc.
            source_disk_image = latest_image.self_link
            logger.info(f"Using source image: {source_disk_image}")

            # 3. Define Machine Type URL
            machine_type_url = f"zones/{zone}/machineTypes/{machine_type}"

            # 4. Prepare Instance Configuration
            logger.info("Preparing instance configuration...")
            instance_config = compute_v1.Instance(
                name=instance_name,
                machine_type=machine_type_url,
                # Network interface (use default network)
                network_interfaces=[compute_v1.NetworkInterface(
                    name="global/networks/default", # Use the default VPC network
                    # Request external IP (AccessConfig)
                    access_configs=[compute_v1.AccessConfig(
                         name="External NAT",
                         type_="ONE_TO_ONE_NAT" # Standard external IP
                    )]
                )],
                # Disks
                disks=[compute_v1.AttachedDisk(
                    initialize_params=compute_v1.AttachedDiskInitializeParams(
                        source_image=source_disk_image,
                        disk_size_gb=10 # Small boot disk
                    ),
                    auto_delete=True, # Delete disk when VM is deleted
                    boot=True # This is the boot disk
                )],
                 # Add SSH key to metadata
                metadata=compute_v1.Metadata(
                    items=[compute_v1.Items(
                        key="ssh-keys",
                        value=ssh_key_metadata
                    )]
                ),
                 # Add tags for identification
                 tags=compute_v1.Tags(
                     items=["ai-devops-instance", "http-server", "https-server"] # Tags for firewall rules
                 )
            )

            # 5. Insert Instance request
            logger.info(f"Submitting instance creation request for '{instance_name}' (this may take a few minutes)...")
            operation = compute_client.insert(
                project=project_id,
                zone=zone,
                instance_resource=instance_config
            )

            # Wait for the operation to complete
            logger.info("Waiting for instance creation operation to complete...")
            operation_client = compute_v1.ZoneOperationsClient(credentials=credentials)
            while operation.status != compute_v1.Operation.Status.DONE:
                 operation = operation_client.wait(
                      project=project_id,
                      zone=zone,
                      operation=operation.name,
                      timeout=120 # Wait up to 2 minutes per check cycle
                 )
                 if operation.error:
                      raise Exception(f"Instance creation failed: {operation.error}")
                 if operation.status == compute_v1.Operation.Status.DONE:
                      logger.info("Instance creation operation finished.")
                      break
                 time.sleep(5) # Wait between checks


            # 6. Get Instance Details (including Public IP)
            logger.info(f"Fetching details for created instance '{instance_name}'...")
            instance_details = compute_client.get(project=project_id, zone=zone, instance=instance_name)
            public_ip = None
            if instance_details.network_interfaces and instance_details.network_interfaces[0].access_configs:
                 public_ip = instance_details.network_interfaces[0].access_configs[0].nat_ip

            self.created_resource_details = {
                'type': 'GCP Compute Engine VM',
                'name': instance_name,
                'id': instance_details.id,
                'project_id': project_id,
                'zone': zone,
                'machine_type': machine_type,
                'public_ip': public_ip,
                'ssh_user': ssh_user,
                'ssh_key_private_path': self.ssh_key_paths.get('private')
            }
            logger.info("GCP Compute Engine Instance Created Successfully:")
            logger.info(f"  Name: {instance_name}")
            logger.info(f"  Public IP: {public_ip}")
            logger.info(f"  SSH User: {ssh_user}")
            logger.info(f"  SSH Key: {self.ssh_key_paths.get('private')}")


            # 7. Create Firewall Rule for SSH (and optionally HTTP/S)
            firewall_client = compute_v1.FirewallsClient(credentials=credentials)
            ssh_firewall_rule_name = "ai-devops-allow-ssh"
            http_firewall_rule_name = "ai-devops-allow-http" # If tags included http-server
            https_firewall_rule_name = "ai-devops-allow-https" # If tags included https-server

            # SSH Rule
            ssh_rule = compute_v1.Firewall(
                 name=ssh_firewall_rule_name,
                 description="Allow SSH access for AI DevOps instances",
                 network="global/networks/default", # Apply to default network
                 priority=1000, # Default priority
                 direction=compute_v1.Firewall.Direction.INGRESS,
                 allowed=[compute_v1.Allowed(
                      ip_protocol="tcp",
                      ports=["22"]
                 )],
                 source_ranges=["0.0.0.0/0"], # Allow from anywhere
                 target_tags=["ai-devops-instance"] # Apply to VMs with this tag
            )
            try:
                 logger.info(f"Checking/Creating firewall rule '{ssh_firewall_rule_name}'...")
                 fw_op = firewall_client.insert(project=project_id, firewall_resource=ssh_rule)
                 # Wait for firewall rule creation (optional, but good practice)
                 # fw_op.result(timeout=60)
                 logger.info(f"Firewall rule '{ssh_firewall_rule_name}' created or already exists.")
            except google_exceptions.Conflict:
                 logger.info(f"Firewall rule '{ssh_firewall_rule_name}' already exists.")
            except Exception as fw_e:
                 logger.warning(f"Could not create SSH firewall rule: {fw_e}. Please check manually.")

            # Add HTTP/HTTPS rules if needed based on tags (similar pattern)

            return True

        except google_exceptions.ApiException as e:
            logger.error(f"GCP API error during VM creation: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during GCP VM creation: {e}", exc_info=True)
            return False

    def generate_cicd_config(self) -> bool:
        """Generate CI/CD pipeline configuration"""
        logger.info("Generating CI/CD pipeline configuration...")
        print("!!! generate_cicd_config METHOD IS BEING CALLED !!!") # Add this line

        repo_info = self.repo_url.lower()
        ci_platform = "github" # Default
        result = False # Default to False

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
        # Check if attribute exists before setting, though it should be fine
        setattr(self, 'ci_platform', ci_platform)
        return result

    
    def _generate_github_actions_config(self):
        """Generate GitHub Actions workflow configuration"""
        logger.info("Generating GitHub Actions workflow...")
        
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
                    'branches': ['main', 'master'] # Consider making configurable
                },
                'pull_request': {
                    'branches': ['main', 'master'] # Consider making configurable
                },
                'workflow_dispatch': {} # Allow manual triggering
            },
            'jobs': {
                'build': {
                    'runs-on': 'ubuntu-latest',
                    'outputs': { # Define outputs if deploy depends on build artifacts
                         'artifact_path': '${{ steps.upload_artifact.outputs.artifact-path }}' # Example
                    },
                    'steps': [
                        {
                            'name': 'Checkout code',
                            'uses': 'actions/checkout@v4' # Use latest major version
                        }
                        # Tech specific build steps will be added here
                    ]
                }
            }
        }

        # --- Add technology-specific build steps ---
        build_steps = workflow['jobs']['build']['steps'] # Get reference to steps list
        artifact_name = "app-build" # Default artifact name

        if self.detected_stack == 'nodejs':
            build_steps.extend([
                {
                    'name': 'Setup Node.js',
                    'uses': 'actions/setup-node@v4',
                    'with': {
                        'node-version': '18' # Use a current LTS version
                    }
                },
                {
                    'name': 'Install dependencies',
                    'run': 'npm ci' # Preferred over npm install for CI
                },
                {
                    'name': 'Run linters (optional)',
                    'run': 'npm run lint --if-present'
                },
                {
                    'name': 'Run tests',
                    # Use --if-present to avoid failure if test script doesn't exist
                    'run': 'npm test --if-present'
                },
                {
                    'name': 'Build application',
                    'run': 'npm run build --if-present'
                }
            ])
            # Define artifact path for Node.js (e.g., build dir or zipped node_modules)
            # This depends heavily on the deployment target.
            # If deploying code directly (e.g., Lambda zip, EC2 sync), artifact might be the whole repo.
            # If deploying container, artifact might be context dir, or no artifact needed if built in deploy job.
            # Example: Zipping the whole directory for Lambda/EC2 deploy
            build_steps.append({
                 'name': 'Archive production artifacts',
                 'run': f'zip -r {artifact_name}.zip . -x ".git*" -x ".github*"'
            })
            artifact_path = f"{artifact_name}.zip"

        elif self.detected_stack == 'python':
            build_steps.extend([
                {
                    'name': 'Setup Python',
                    'uses': 'actions/setup-python@v5', # Use latest major version
                    'with': {
                        'python-version': '3.10' # Use a current version
                    }
                },
                {
                    'name': 'Install dependencies',
                    # Consider using venv for isolation
                    'run': f"""
                        python -m venv venv
                        source venv/bin/activate
                        pip install --upgrade pip
                        if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
                        if [ -f setup.py ]; then pip install .; fi
                    """
                },
                {
                    'name': 'Run linters (e.g., flake8, black - optional)',
                    'run': f"""
                        source venv/bin/activate
                        # pip install flake8 black # Install if needed
                        # flake8 .
                        # black --check .
                        echo "Linting step placeholder"
                    """
                },
                {
                    'name': 'Run tests (e.g., pytest)',
                    'run': f"""
                        source venv/bin/activate
                        # pip install pytest # Install if needed
                        pytest || echo "Pytest not found or no tests run."
                    """
                }
            ])
             # Example: Zipping the whole directory including venv for Lambda/EC2
            build_steps.append({
                 'name': 'Archive production artifacts',
                 # Exclude unnecessary files. Include venv if needed for deployment target.
                 'run': f'zip -r {artifact_name}.zip . -x ".git*" -x ".github*" -x "__pycache__*" -x "*.pyc"'
            })
            artifact_path = f"{artifact_name}.zip"

        elif self.detected_stack == 'java':
            # Determine build tool (Maven/Gradle)
            is_maven = os.path.exists(os.path.join(self.repo_path, 'pom.xml'))
            is_gradle = os.path.exists(os.path.join(self.repo_path, 'build.gradle')) or \
                        os.path.exists(os.path.join(self.repo_path, 'build.gradle.kts'))
            build_tool_cmd = ""
            build_artifact_path = "target/*.jar" # Maven default, adjust for WAR/Gradle

            if is_maven:
                 build_tool_cmd = "mvn -B package --file pom.xml" # -B for non-interactive
                 # Find artifact path more dynamically if possible, or assume common pattern
                 # Could parse pom.xml for artifactId/version, but complex. Assume jar in target.
                 logger.info("Detected Maven project.")
            elif is_gradle:
                 # Gradle wrapper is preferred if it exists
                 gradle_executable = "./gradlew" if os.path.exists(os.path.join(self.repo_path, 'gradlew')) else "gradle"
                 build_tool_cmd = f"{gradle_executable} build -x test" # Build without running tests again
                 build_artifact_path = "build/libs/*.jar" # Gradle default, adjust for WAR etc.
                 logger.info("Detected Gradle project.")
            else:
                 logger.warning("Java project detected, but couldn't determine build tool (Maven/Gradle). Using placeholder build command.")
                 build_tool_cmd = "echo 'Build command placeholder for Java'"
                 build_artifact_path = "./" # Unknown path

            build_steps.extend([
                {
                    'name': 'Setup Java',
                    'uses': 'actions/setup-java@v4', # Use latest major version
                    'with': {
                        'distribution': 'temurin', # Popular distribution
                        'java-version': '17' # Use a current LTS
                    }
                },
                 # Cache dependencies (Maven/Gradle) - Improves speed
                {
                    'name': f'Cache { "Maven" if is_maven else "Gradle"} packages',
                    'uses': 'actions/cache@v4', # Use latest major version
                    'with': {
                         'path': '~/.m2/repository' if is_maven else '~/.gradle/caches',
                         'key': '${{ runner.os }}-' + ('maven' if is_maven else 'gradle') + '-${{ hashFiles(' + ("**/pom.xml" if is_maven else "**/*.gradle*") + ') }}',
                         'restore-keys': f"""
                              ${{ runner.os }}-{'maven' if is_maven else 'gradle'}-
                         """
                    }
                },
                {
                    'name': f'Build with {"Maven" if is_maven else "Gradle"}',
                    'run': build_tool_cmd
                }
                # Tests are often run as part of the build (mvn package / gradle build)
            ])
            # Upload the built artifact (JAR/WAR)
            build_steps.append({
                 'name': 'Upload build artifact',
                 'uses': 'actions/upload-artifact@v4', # Use latest major version
                 'with': {
                      'name': artifact_name,
                      'path': build_artifact_path
                 }
            })
            # Output path for deploy job to download
            workflow['jobs']['build']['outputs']['artifact_path'] = artifact_path # Store the pattern/path

        elif self.detected_stack == 'golang':
            build_steps.extend([
                {
                    'name': 'Setup Go',
                    'uses': 'actions/setup-go@v5', # Use latest major version
                    'with': {
                        'go-version': '^1.19' # Use a current version
                    }
                },
                {
                    'name': 'Build',
                    'run': 'go build -v -o myapp ./...' # Build executable named 'myapp'
                },
                {
                    'name': 'Test',
                    'run': 'go test -v ./...'
                }
            ])
            # Upload the executable
            artifact_path = "myapp"
            build_steps.append({
                 'name': 'Upload build artifact',
                 'uses': 'actions/upload-artifact@v4',
                 'with': {
                      'name': artifact_name,
                      'path': artifact_path
                 }
            })
            workflow['jobs']['build']['outputs']['artifact_path'] = artifact_path


        # --- Add deployment job ---
        # Deployment depends heavily on the *target service* within the cloud provider
        deploy_job = {
            'needs': 'build', # Depends on the build job
            'runs-on': 'ubuntu-latest',
             # Conditional execution: only run on push to main/master, not on PRs
            'if': "github.event_name == 'push' || github.event_name == 'workflow_dispatch'",
            'environment': { # Optional: Define deployment environment for approvals/secrets
                 'name': 'production', # Example environment name
                 # 'url': 'https://my-app-url.com' # Optional: Link to deployed app
            },
            'steps': [
                # Standard checkout is often needed again in the deploy job
                {
                    'name': 'Checkout code',
                    'uses': 'actions/checkout@v4'
                },
                # Download artifact from build job if needed (e.g., for EC2, Lambda)
                # Not always needed if deploying a container built in this job.
                # {
                #      'name': 'Download build artifact',
                #      'uses': 'actions/download-artifact@v4',
                #      'with': {
                #           'name': artifact_name # Use the same name as upload
                #           # 'path': '.' # Optional: download to specific directory
                #      }
                # },
                # Unzip artifact if it was zipped
                # {
                #      'name': 'Unzip artifact',
                #      'run': f'unzip {artifact_path}' # Use the artifact path (e.g., app-build.zip)
                #      # 'if': "needs.build.outputs.artifact_path == '*.zip'" # Condition if zipped
                # }
            ]
        }

        # Get reference to deploy steps for easier modification
        deploy_steps = deploy_job['steps']

        # --- Cloud Provider Specific Deployment Steps ---
        if self.cloud_provider == 'aws':
            # Common AWS credential setup
            aws_creds_step = {
                 'name': 'Configure AWS Credentials',
                 'uses': 'aws-actions/configure-aws-credentials@v4', # Use latest major version
                 'with': {
                      # Use secrets defined in GitHub repository settings
                      'aws-access-key-id': '${{ secrets.AWS_ACCESS_KEY_ID }}',
                      'aws-secret-access-key': '${{ secrets.AWS_SECRET_ACCESS_KEY }}',
                      # Optional: session token if using temporary credentials
                      # 'aws-session-token': '${{ secrets.AWS_SESSION_TOKEN }}',
                      'aws-region': self.cloud_credentials['region'] # Use region determined earlier
                 }
            }
            deploy_steps.append(aws_creds_step)

            # --- Target Specific AWS Deploy Steps ---
            if self.resource_configuration['type'] == 'ec2':
                 # Need artifact for EC2 deployment
                 deploy_steps.insert(1, { # Insert after checkout
                      'name': 'Download build artifact',
                      'uses': 'actions/download-artifact@v4',
                      'with': {'name': artifact_name}
                 })
                 deploy_steps.insert(2, { # Insert after download
                      'name': 'Unzip artifact',
                      'run': f'unzip {artifact_name}.zip' # Assuming artifact is zipped
                 })
                 # Get EC2 instance details (assuming it was created and details stored)
                 # In a real-world scenario, you might query the instance ID/IP using tags
                 instance_id = self.created_resource_details.get('id', 'INSTANCE_ID_PLACEHOLDER')
                 public_ip = self.created_resource_details.get('public_ip', 'PUBLIC_IP_PLACEHOLDER')
                 ssh_user = self.created_resource_details.get('ssh_user', 'ec2-user')
                 ssh_key_name = self.ssh_key_paths.get('key_name', 'ai-devops-ec2-key') # AWS Key name

                 # Simple deployment using SSH/SCP or SSM Run Command
                 # Option 1: Using SSM Run Command (more secure, needs SSM agent on EC2)
                 # deploy_steps.append({
                 #      'name': 'Deploy to EC2 via SSM',
                 #      'run': f"""
                 #           echo "Deploying application update..."
                 #           # Example: Stop service, copy files (needs pre-sync?), start service
                 #           aws ssm send-command --instance-ids "${{ env.INSTANCE_ID }}" \
                 #                --document-name "AWS-RunShellScript" \
                 #                --parameters 'commands=["sudo systemctl stop myapp || true", "echo Placeholder for file sync", "sudo systemctl start myapp"]' \
                 #                --comment "Deploy triggered by GitHub Actions ${{ github.sha }}" \
                 #                --output text --query "Command.CommandId"
                 #      """
                 #      'env': { 'INSTANCE_ID': instance_id }
                 # })
                 # Option 2: Using SSH (requires setting up SSH key as secret)
                 deploy_steps.append({
                    'name': 'Setup SSH Key',
                    'run': f"""
                         echo "${{ secrets.EC2_SSH_PRIVATE_KEY }}" > private_key.pem
                         chmod 600 private_key.pem
                    """ # Add secrets.EC2_SSH_PRIVATE_KEY to GitHub repo secrets
                    })
                 deploy_steps.append({
                    'name': 'Deploy to EC2 via SCP & SSH',
                    'run': f"""
                         echo "Deploying application files via SCP..."
                         # Use -o StrictHostKeyChecking=no for first connection (use with caution)
                         scp -o StrictHostKeyChecking=no -i private_key.pem -r ./* ${{ env.SSH_USER }}@${{ env.PUBLIC_IP }}:/path/to/app/destination
                         echo "Executing remote commands via SSH..."
                         ssh -o StrictHostKeyChecking=no -i private_key.pem ${{ env.SSH_USER }}@${{ env.PUBLIC_IP }} << EOF
                              echo "Running deployment script on server..."
                              cd /path/to/app/destination
                              # Commands to restart your application, e.g.:
                              # npm install --production # If node_modules weren't zipped
                              # pm2 restart myapp || pm2 start ecosystem.config.js
                              # sudo systemctl restart myapp.service
                              echo "Deployment commands finished."
                         EOF
                    """,
                    'env': {
                         'PUBLIC_IP': public_ip,
                         'SSH_USER': ssh_user
                    }
                    })  # Added the missing closing parenthesis here


            elif self.resource_configuration['type'] == 'ecs':
                 cluster_name = self.created_resource_details.get('name', 'ai-devops-cluster') # Use created cluster name
                 service_name = 'ai-devops-service' # Assume a service name convention
                 task_def_file = 'task-definition.json' # Assume task def file exists in repo
                 ecr_repo_name = f"ai-devops/{self.repo_url.split('/')[-1].replace('.git', '')}" # Example ECR repo name

                 deploy_steps.extend([
                      {
                           'name': 'Login to Amazon ECR',
                           'id': 'login-ecr',
                           'uses': 'aws-actions/amazon-ecr-login@v2' # Use latest major version
                      },
                      {
                           'name': 'Build, Tag, and Push Docker image to Amazon ECR',
                           'id': 'build-image',
                           'env': {
                                'ECR_REGISTRY': '${{ steps.login-ecr.outputs.registry }}',
                                'ECR_REPOSITORY': ecr_repo_name,
                                'IMAGE_TAG': '${{ github.sha }}' # Use commit SHA as tag
                           },
                           'run': f"""
                                # Check if Dockerfile exists
                                if [ ! -f Dockerfile ]; then
                                     echo "Dockerfile not found in repository root. Cannot build image."
                                     exit 1
                                fi
                                docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
                                docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
                                echo "::set-output name=image::$ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG"
                           """
                      },
                      {
                            'name': 'Download task definition template', # Or generate dynamically
                            'run': f'aws ecs describe-task-definition --task-definition {service_name} --query taskDefinition > {task_def_file} || echo "Task definition not found, using placeholder." '
                            # Placeholder if task def doesn't exist yet (first deploy)
                            # 'run': f'echo \'{ "family": "{service_name}", "containerDefinitions": [ ... ] }\' > {task_def_file}'
                      },
                      {
                           'name': 'Fill in the new image ID in the Amazon ECS task definition',
                           'id': 'task-def',
                           'uses': 'aws-actions/amazon-ecs-render-task-definition@v1',
                           'with': {
                                'task-definition': task_def_file,
                                'container-name': service_name, # Assume container name matches service name
                                'image': '${{ steps.build-image.outputs.image }}'
                           }
                      },
                      {
                           'name': 'Deploy Amazon ECS task definition',
                           'uses': 'aws-actions/amazon-ecs-deploy-task-definition@v1',
                           'with': {
                                'task-definition': '${{ steps.task-def.outputs.task-definition }}',
                                'service': service_name,
                                'cluster': cluster_name,
                                'wait-for-service-stability': 'true' # Wait for deployment to stabilize
                           }
                      }
                 ])


            elif self.resource_configuration['type'] == 'lambda':
                 function_name = self.created_resource_details.get('name', 'ai-devops-function')
                 # Need zipped artifact
                 deploy_steps.insert(1, { # Insert after checkout
                      'name': 'Download build artifact',
                      'uses': 'actions/download-artifact@v4',
                      'with': {'name': artifact_name}
                 })
                 # Artifact should be named e.g., app-build.zip from build job
                 artifact_zip_path = f"{artifact_name}.zip"

                 deploy_steps.append({
                      'name': 'Deploy code to AWS Lambda',
                      'run': f"""
                           aws lambda update-function-code --function-name "${{ env.FUNCTION_NAME }}" --zip-file "fileb://${{ env.ARTIFACT_PATH }}" --publish
                           echo "Lambda deployment initiated."
                           # Optional: Wait for update to complete
                           aws lambda wait function-updated --function-name "${{ env.FUNCTION_NAME }}"
                           echo "Lambda function update complete."
                      """,
                      'env': {
                           'FUNCTION_NAME': function_name,
                           'ARTIFACT_PATH': artifact_zip_path
                      }
                 })


        elif self.cloud_provider == 'azure':
             # Common Azure login
             azure_login_step = {
                  'name': 'Azure Login',
                  'uses': 'azure/login@v1',
                  'with': {
                       # Use secrets defined in GitHub repository settings
                       # Recommended: Use OIDC Connect or Service Principal with federated credentials
                       # Option 1: OIDC (Recommended) - Needs setup in Azure AD and GitHub Actions
                       # 'client-id': '${{ secrets.AZURE_CLIENT_ID }}',
                       # 'tenant-id': '${{ secrets.AZURE_TENANT_ID }}',
                       # 'subscription-id': '${{ secrets.AZURE_SUBSCRIPTION_ID }}',
                       # 'enable-AzPSSession': 'true' # Optional for PowerShell Az module
                       # Option 2: Service Principal Secret
                       'creds': '${{ secrets.AZURE_CREDENTIALS }}' # JSON object with SP details
                       # Example AZURE_CREDENTIALS secret format:
                       # {
                       #   "clientId": "...",
                       #   "clientSecret": "...",
                       #   "subscriptionId": "...",
                       #   "tenantId": "..."
                       # }
                  }
             }
             deploy_steps.append(azure_login_step)

             # --- Target Specific Azure Deploy Steps ---
             if self.resource_configuration['type'] == 'vm':
                  # Need artifact
                  deploy_steps.insert(1, {
                       'name': 'Download build artifact',
                       'uses': 'actions/download-artifact@v4',
                       'with': {'name': artifact_name}
                  })
                  deploy_steps.insert(2, {
                       'name': 'Unzip artifact',
                       'run': f'unzip {artifact_name}.zip'
                  })
                  # Get VM details
                  vm_name = self.created_resource_details.get('name', 'ai-devops-vm')
                  rg_name = self.created_resource_details.get('resource_group', 'ai-devops-rg')
                  public_ip = self.created_resource_details.get('public_ip', 'PUBLIC_IP_PLACEHOLDER')
                  admin_user = self.created_resource_details.get('admin_username', 'azureuser')

                  # Option 1: Using Run Command (needs VM agent, similar to AWS SSM)
                  # deploy_steps.append({
                  #      'name': 'Deploy to Azure VM via Run Command',
                  #      'uses': 'azure/CLI@v1',
                  #      'with': {
                  #           'inlineScript': f"""
                  #                echo "Deploying application update via Run Command..."
                  #                # Example: Stop service, copy files (needs way to get files there), start service
                  #                az vm run-command invoke --resource-group ${{ env.RESOURCE_GROUP }} --name ${{ env.VM_NAME }} \
                  #                     --command-id RunShellScript \
                  #                     --scripts "sudo systemctl stop myapp || true; echo Placeholder for file sync; sudo systemctl start myapp"
                  #           """
                  #           'env': {
                  #                'RESOURCE_GROUP': rg_name,
                  #                'VM_NAME': vm_name
                  #           }
                  #      }
                  # })
                  # Option 2: Using SSH (requires SSH key as secret)
                  deploy_steps.append({
                      'name': 'Setup SSH Key',
                      'run': f"""
                           echo "${{ secrets.AZURE_VM_SSH_PRIVATE_KEY }}" > private_key.pem
                           chmod 600 private_key.pem
                      """ # Add secrets.AZURE_VM_SSH_PRIVATE_KEY to GitHub repo secrets
                  })
                  deploy_steps.append({
                      'name': 'Deploy to Azure VM via SCP & SSH',
                      'run': f"""
                           echo "Deploying application files via SCP..."
                           scp -o StrictHostKeyChecking=no -i private_key.pem -r ./* ${{ env.ADMIN_USER }}@${{ env.PUBLIC_IP }}:/path/to/app/destination
                           echo "Executing remote commands via SSH..."
                           ssh -o StrictHostKeyChecking=no -i private_key.pem ${{ env.ADMIN_USER }}@${{ env.PUBLIC_IP }} << EOF
                               echo "Running deployment script on server..."
                               cd /path/to/app/destination
                               # Commands to restart your application
                               # e.g., sudo systemctl restart myapp.service
                               echo "Deployment commands finished."
                           EOF
                      """,
                      'env': {
                           'PUBLIC_IP': public_ip,
                           'ADMIN_USER': admin_user
                      }
                  })

             elif self.resource_configuration['type'] == 'app_service':
                  app_name = self.created_resource_details.get('name', 'ai-devops-webapp')
                  # Deployment depends on stack (zip deploy, container deploy, etc.)
                  # Assuming Zip Deploy for Node/Python/Java artifact
                  deploy_steps.insert(1, { # Download the zipped artifact
                       'name': 'Download build artifact',
                       'uses': 'actions/download-artifact@v4',
                       'with': {'name': artifact_name}
                  })
                  artifact_zip_path = f"{artifact_name}.zip"

                  deploy_steps.append({
                       'name': 'Deploy to Azure Web App',
                       'uses': 'azure/webapps-deploy@v2',
                       'with': {
                            'app-name': app_name,
                            'package': artifact_zip_path, # Deploy the zipped artifact
                            # Add slot-name: 'staging' for slot deployment
                       }
                  })


        elif self.cloud_provider == 'gcp':
            # Common GCP Auth setup
            # Recommended: Use Workload Identity Federation (OIDC)
            gcp_auth_step = {
                 'name': 'Authenticate to Google Cloud',
                 'id': 'auth',
                 'uses': 'google-github-actions/auth@v1', # Use latest major version
                 'with': {
                      # Option 1: Workload Identity Federation (Recommended) - Needs setup in GCP IAM & GitHub Actions
                      # 'workload_identity_provider': 'projects/${{ secrets.GCP_PROJECT_NUMBER }}/locations/global/workloadIdentityPools/${{ secrets.GCP_WIF_POOL_ID }}/providers/${{ secrets.GCP_WIF_PROVIDER_ID }}',
                      # 'service_account': '${{ secrets.GCP_SA_EMAIL }}', # Service account to impersonate
                      # Option 2: Service Account Key JSON (Less Secure)
                      'credentials_json': '${{ secrets.GCP_SA_KEY }}' # Store the JSON key content as a secret
                 }
            }
            deploy_steps.append(gcp_auth_step)
            # Set project ID for gcloud commands
            deploy_steps.append({
                 'name': 'Set up Cloud SDK',
                 'uses': 'google-github-actions/setup-gcloud@v1',
                 'with': {
                      'project_id': self.cloud_credentials['project_id'],
                 }
            })

            # --- Target Specific GCP Deploy Steps ---
            if self.resource_configuration['type'] == 'vm':
                 # Need artifact
                 deploy_steps.insert(1, {
                      'name': 'Download build artifact',
                      'uses': 'actions/download-artifact@v4',
                      'with': {'name': artifact_name}
                 })
                 deploy_steps.insert(2, {
                      'name': 'Unzip artifact',
                      'run': f'unzip {artifact_name}.zip'
                 })
                 # Get VM details
                 instance_name = self.created_resource_details.get('name', 'ai-devops-instance')
                 zone = self.created_resource_details.get('zone', 'us-central1-a')
                 project_id = self.created_resource_details.get('project_id', 'GCP_PROJECT_ID')
                 # Public IP might change, better to use gcloud to get it or rely on instance name
                 # ssh_user = self.created_resource_details.get('ssh_user', 'gcpuser')

                 # Deploy using gcloud compute scp and ssh
                 # gcloud handles SSH key management more seamlessly than manual SSH if keys are added to project/instance metadata
                 deploy_steps.append({
                      'name': 'Deploy to GCE via gcloud',
                      'run': f"""
                           echo "Deploying application files via gcloud compute scp..."
                           # Use --project and --zone flags
                           gcloud compute scp --project=${{ env.PROJECT_ID }} --zone=${{ env.ZONE }} --recurse ./ ${{ env.INSTANCE_NAME }}:/path/to/app/destination

                           echo "Executing remote commands via gcloud compute ssh..."
                           gcloud compute ssh --project=${{ env.PROJECT_ID }} --zone=${{ env.ZONE }} ${{ env.INSTANCE_NAME }} --command=" \
                                echo 'Running deployment script on server...'; \
                                cd /path/to/app/destination; \
                                # Add commands to restart your application here, e.g.: \
                                # sudo systemctl restart myapp.service \
                                echo 'Deployment commands finished.' \
                           "
                      """,
                      'env': {
                           'PROJECT_ID': project_id,
                           'ZONE': zone,
                           'INSTANCE_NAME': instance_name
                      }
                 })

            elif self.resource_configuration['type'] == 'cloud_run':
                 service_name = self.created_resource_details.get('name', 'ai-devops-service')
                 region = self.created_resource_details.get('region', 'us-central1')
                 project_id = self.created_resource_details.get('project_id', 'GCP_PROJECT_ID')
                 # Cloud Run needs a container image
                 # Assume Dockerfile exists and build/push here

                 # Define image name in GCR or Artifact Registry
                 # Using Artifact Registry is recommended over GCR
                 # Example: AR Repo: projects/PROJECT_ID/locations/REGION/repositories/REPOSITORY_NAME
                 # Example: GCR Host: gcr.io, us.gcr.io, eu.gcr.io, asia.gcr.io
                 image_name = f"gcr.io/{project_id}/{service_name}" # Simple GCR example
                 # image_name = f"{region}-docker.pkg.dev/{project_id}/my-repo/{service_name}" # Artifact Registry example

                 deploy_steps.extend([
                      {
                           'name': 'Configure Docker for GCP',
                           'run': 'gcloud auth configure-docker --quiet' # Configures GCR access
                           # For Artifact Registry: gcloud auth configure-docker {region}-docker.pkg.dev --quiet
                      },
                      {
                           'name': 'Build and Push Docker image',
                           'run': f"""
                                if [ ! -f Dockerfile ]; then
                                     echo "Dockerfile not found. Cannot build image for Cloud Run."
                                     exit 1
                                fi
                                docker build -t "${{ env.IMAGE_NAME }}:${{ github.sha }}" .
                                docker push "${{ env.IMAGE_NAME }}:${{ github.sha }}"
                           """,
                           'env': { 'IMAGE_NAME': image_name }
                      },
                      {
                           'name': 'Deploy to Cloud Run',
                           'run': f"""
                                gcloud run deploy "${{ env.SERVICE_NAME }}" \
                                     --image "${{ env.IMAGE_NAME }}:${{ github.sha }}" \
                                     --region "${{ env.REGION }}" \
                                     --project "${{ env.PROJECT_ID }}" \
                                     --platform managed \
                                     --allow-unauthenticated # Or --no-allow-unauthenticated
                                     # Add other flags like --memory, --cpu, --port, --env-vars-file as needed
                           """,
                           'env': {
                                'SERVICE_NAME': service_name,
                                'REGION': region,
                                'PROJECT_ID': project_id,
                                'IMAGE_NAME': image_name
                           }
                      }
                 ])


        # --- Finalize Workflow ---
        # Add the deployment job to the workflow dictionary
        workflow['jobs']['deploy'] = deploy_job

        # Write workflow configuration to file
        try:
            with open(workflow_file, 'w') as f:
                # Use sort_keys=False to maintain order (on newer PyYAML versions)
                yaml.dump(workflow, f, default_flow_style=False, sort_keys=False)
            logger.info(f"GitHub Actions workflow file created/updated: {workflow_file}")
            return True
        except Exception as e:
            logger.error(f"Error writing YAML workflow file: {e}")
            return False
            # Consider not proceeding if the core workflow file fails


    def _generate_gitlab_ci_config(self):
        """Generate GitLab CI configuration"""
        # --- (Implementation similar to GitHub Actions, adapting syntax for GitLab CI) ---
        # Key differences:
        # - Stages definition (`stages: [build, test, deploy]`)
        # - Job definitions (`build_job:`, `test_job:`, `deploy_job:`)
        # - `image:` keyword for Docker image per job
        # - `script:` block for commands
        # - `artifacts:` for passing files between stages
        # - `variables:` for environment variables (can be set at group/project level too)
        # - `only:` or `rules:` for controlling when jobs run
        # - Caching uses `cache:` keyword
        # - Needs cloud provider CLI tools in the job image or installed in `before_script`
        # - Secrets/variables accessed via `$VARIABLE_NAME` (e.g., $AWS_ACCESS_KEY_ID)
        logger.info("Generating GitLab CI configuration...")
        # Placeholder - Full implementation requires translating all GitHub Actions steps
        # Example Snippet for AWS EC2 deploy:
        # deploy_aws_ec2:
        #   stage: deploy
        #   image: amazon/aws-cli # Or build your own image with tools + aws cli
        #   before_script:
        #     - '[ -f app-build.zip ] || (echo "Build artifact not found!" && exit 1)' # Ensure artifact exists
        #     - unzip app-build.zip
        #     - yum update -y && yum install -y openssh-clients # Install SSH if not in image
        #     - echo "$EC2_SSH_PRIVATE_KEY" > private_key.pem # Variable from GitLab CI/CD settings
        #     - chmod 600 private_key.pem
        #   script:
        #     - scp -o StrictHostKeyChecking=no -i private_key.pem -r ./ $SSH_USER@$PUBLIC_IP:/path/to/app
        #     - ssh -o StrictHostKeyChecking=no -i private_key.pem $SSH_USER@$PUBLIC_IP "cd /path/to/app && sudo systemctl restart myapp"
        #   variables: # Pass details (can also come from GitLab Variables UI)
        #      PUBLIC_IP: ${self.created_resource_details.get('public_ip', 'YOUR_EC2_IP')}
        #      SSH_USER: ${self.created_resource_details.get('ssh_user', 'ec2-user')}
        #   rules:
        #     - if: '$CI_COMMIT_BRANCH == "main" || $CI_COMMIT_BRANCH == "master"'
        #       when: on_success
        #     - when: never # Don't run otherwise

        ci_file_path = os.path.join(self.repo_path, '.gitlab-ci.yml')
        try:
          with open(ci_file_path, 'w') as f:
               detected_stack = self.detected_stack  # Use local variables instead of nested f-strings
               cloud_provider = self.cloud_provider
               resource_type = self.resource_configuration.get('type', 'resource')
               resource_details = json.dumps(self.created_resource_details)
               
               f.write("# Placeholder for GitLab CI/CD configuration\n")
               f.write("# Please adapt the GitHub Actions workflow logic to GitLab CI syntax.\n")
               
               f.write(f"""
     stages:
     - build
     - deploy

     build_app:
     stage: build
     image: node:18 # Example for Node.js
     script:
     - echo "Running build steps for {detected_stack}..."
     - |
          if [ "{detected_stack}" == "nodejs" ]; then
          npm ci
          npm run build --if-present
          zip -r app-build.zip . -x ".git*" -x ".gitlab-ci.yml"
          elif [ "{detected_stack}" == "python" ]; then
          python -m venv venv && source venv/bin/activate
          pip install -r requirements.txt
          zip -r app-build.zip . -x ".git*" -x ".gitlab-ci.yml" -x "venv/*"
          # Add other stacks
          else
          echo "Build script not implemented for {detected_stack}"
          touch app-build.zip # Create dummy artifact to avoid failure
          fi
     artifacts:
     paths:
          - app-build.zip
     expire_in: 1 hour

     # Example Deploy Job Placeholder (Needs specific implementation)
     deploy_app:
     stage: deploy
     image: alpine:latest # Needs appropriate tools (aws-cli, az-cli, gcloud-sdk, ssh, etc.)
     script:
     - echo "Deploy script placeholder for {cloud_provider} {resource_type}"
     - echo "Resource details: {resource_details}"
     - echo "You need to install necessary CLI tools and use GitLab CI/CD variables for secrets."
     - |
          # Example for AWS EC2 (requires aws-cli, ssh client, and variables like $AWS_ACCESS_KEY_ID, $EC2_SSH_PRIVATE_KEY etc.)
          # apk add --no-cache aws-cli openssh-client
          # export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
          # export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
          # export AWS_DEFAULT_REGION=$AWS_REGION
          # echo "$EC2_SSH_PRIVATE_KEY" > key.pem && chmod 600 key.pem
          # scp -i key.pem -o StrictHostKeyChecking=no -r /opt/atlassian/pipelines/agent/build/app-build.zip $SSH_USER@$SERVER:/tmp/
          # ssh -i key.pem -o StrictHostKeyChecking=no $SSH_USER@$SERVER "unzip -o /tmp/app-build.zip -d /app/deploy && cd /app/deploy && ./restart_script.sh"

     rules:
     - if: '$CI_COMMIT_BRANCH == "main" || $CI_COMMIT_BRANCH == "master"'
          when: on_success
     - when: never
     """)

          logger.info(f"Basic GitLab CI configuration file created: {ci_file_path}")
          return True
        except:
          return False


    def _generate_bitbucket_pipelines_config(self):
        """Generate Bitbucket Pipelines configuration"""
        # --- (Implementation similar to GitHub Actions, adapting syntax for Bitbucket Pipelines) ---
        # Key differences:
        # - `image:` keyword at the top level or per step
        # - `pipelines:` structure (`default:`, `branches:`, `custom:`)
        # - `step:` definition with `name:`, `script:`, `artifacts:`, `caches:`, `services:`
        # - Artifacts are automatically passed between consecutive steps if configured.
        # - Caching uses `caches:` keyword (e.g., `caches: - node`)
        # - Secrets/variables accessed via `$VARIABLE_NAME` (set in Repository settings > Repository variables)
        # - Uses Docker images for execution environment.
        # - Atlassian provides "pipes" for common tasks (e.g., `pipe: atlassian/aws-ecs-deploy:1.4.1`)
        logger.info("Generating Bitbucket Pipelines configuration...")
        # Placeholder - Requires translating GitHub logic to Bitbucket syntax
        # Example Snippet for AWS EC2 deploy using SCP/SSH pipe:
        # pipelines:
        #   branches:
        #     main: # Or master
        #       - step:
        #           name: Build Application
        #           image: node:18 # Example for Node
        #           caches:
        #             - node
        #           script:
        #             - npm ci
        #             - npm run build --if-present
        #             - zip -r app-build.zip . -x ".git*" -x "bitbucket-pipelines.yml"
        #           artifacts:
        #             - app-build.zip
        #       - step:
        #           name: Deploy to AWS EC2
        #           deployment: production # Environment name (optional)
        #           trigger: manual # Or automatic
        #           script:
        #             # Use a pipe for SSH commands
        #             - pipe: atlassian/ssh-run:0.4.0 # Check for latest version
        #               variables:
        #                 SSH_USER: ${SSH_USER} # Repo variable
        #                 SERVER: ${PUBLIC_IP} # Repo variable
        #                 SSH_KEY: ${EC2_SSH_PRIVATE_KEY_BASE64} # Base64 encoded key as repo variable
        #                 COMMAND: f"""
        #                      echo "Uploading artifact..."
        #                      # Need scp within the pipe's container or use a different pipe/manual scp step before
        #                      # This pipe primarily runs remote commands. File transfer is separate.
        #                      # Example assuming scp is available in the pipe's image or use a custom image:
        #                      # scp -i $HOME/.ssh/id_rsa_tmp -r /opt/atlassian/pipelines/agent/build/app-build.zip $SSH_USER@$SERVER:/tmp/
        #                      # ssh -i $HOME/.ssh/id_rsa_tmp $SSH_USER@$SERVER "unzip -o /tmp/app-build.zip -d /app/deploy && cd /app/deploy && ./restart.sh"
        #                      echo "Remote command placeholder: restart application"
        #                      # Replace with actual commands
        #                 MODE: 'command'

        bb_file_path = os.path.join(self.repo_path, 'bitbucket-pipelines.yml')
        detected_stack = self.detected_stack  # Store variables locally to use in the f-string
        cloud_provider = self.cloud_provider
        resource_type = self.resource_configuration.get('type', 'resource')
        resource_details = json.dumps(self.created_resource_details)
        try:
          with open(bb_file_path, 'w') as f:
                    f.write("# Placeholder for Bitbucket Pipelines configuration\n")
                    f.write("# Please adapt the GitHub Actions workflow logic to Bitbucket Pipelines syntax.\n")
                    f.write(f"""
     image: node:18 # Default image, can be overridden per step

     pipelines:
     default: # Runs for any branch push without a specific branch pipeline
     - step:
          name: Build and Test (Default)
          caches:
               - node # Example cache
          script:
               - echo "Running default build for {detected_stack}..."
               - |
               if [ "{detected_stack}" == "nodejs" ]; then
               npm ci
               npm test --if-present
               # Add other stacks
               else
               echo "Build/Test script not implemented for {detected_stack}"
               fi

     branches:
     main: # Pipeline for the main branch
          - step:
               name: Build (Main)
               caches:
               - node
               script:
               - echo "Running main branch build for {detected_stack}..."
               - |
               if [ "{detected_stack}" == "nodejs" ]; then
                    npm ci
                    npm run build --if-present
                    zip -r app-build.zip . -x ".git*" -x "bitbucket-pipelines.yml"
               # Add other stacks
               else
                    echo "Build script not implemented for {detected_stack}"
                    touch app-build.zip
               fi
               artifacts: # Define artifacts to pass to the next step
               - app-build.zip
          - step:
               name: Deploy (Main)
               deployment: production # Mark as production deployment
               trigger: manual # Optional: require manual trigger in Bitbucket UI
               script:
               - echo "Deploy script placeholder for {cloud_provider} {resource_type}"
               - echo "Resource details: {resource_details}"
               - echo "You need to use Bitbucket Pipes or install CLIs/tools in the step's image."
               - echo "Use Repository variables for secrets (e.g., \$AWS_SECRET_ACCESS_KEY, \$AZURE_CREDENTIALS_JSON, \$GCP_SA_KEY_BASE64)."
               - |
               # Example using AWS CLI pipe (needs variables set in Bitbucket)
               # pipe: atlassian/aws-cli-run:1.5.0
               # variables:
               #   AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID
               #   AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY
               #   AWS_DEFAULT_REGION: $AWS_REGION
               #   COMMAND: 'echo "Running AWS deployment command..."'
               #   # aws lambda update-function-code --function-name my-func --zip-file fileb://app-build.zip
               #   # aws ecs update-service ...
     """)
          logger.info(f"Basic Bitbucket Pipelines configuration file created: {bb_file_path}")
          return True
        except Exception as e:
             logger.error(f"Error writing Bitbucket Pipelines file: {e}")
             return False

    # --- [ commit_changes remains the same ] ---
    def commit_changes(self) -> bool:
        """Commit CI/CD configuration changes to the repository"""
        logger.info("Committing changes to repository...")

        # Ensure .gitignore exists and includes sensitive files if generated
        gitignore_path = os.path.join(self.repo_path, '.gitignore')
        added_to_gitignore = []
        gitignore_content = ""
        if os.path.exists(gitignore_path):
             with open(gitignore_path, 'r') as f_read:
                  gitignore_content = f_read.read()

        with open(gitignore_path, 'a') as f_append: # Open in append mode
             # Add generated private keys if they exist and aren't already ignored
             if self.ssh_key_paths.get('private'):
                  key_file_name = os.path.basename(self.ssh_key_paths['private'])
                  if key_file_name not in gitignore_content:
                       f_append.write(f"\n# AI DevOps Generated Keys\n{key_file_name}\n")
                       added_to_gitignore.append(key_file_name)
                       logger.info(f"Added '{key_file_name}' to .gitignore")

             # Add other potentially sensitive generated files if needed
             # Example: if storing cloud creds temporarily (though shouldn't)
             # if 'temp_creds.json' not in gitignore_content:
             #      f_append.write('temp_creds.json\n')
             #      added_to_gitignore.append('temp_creds.json')

        try:
            repo = Repo(self.repo_path)

            # Stage all changes, including .gitignore and workflow files
            repo.git.add(A=True) # Use A=True to stage all changes (new, modified, deleted)

            # Check if there are changes to commit
            if not repo.is_dirty(untracked_files=True):
                 logger.info("No changes detected in the repository to commit.")
                 # Decide if this is an error or just info. If pipeline file was expected, maybe warn.
                 # Check if expected workflow files exist:
                 workflow_files_exist = False
                 if 'github.com' in self.repo_url.lower():
                      workflow_files_exist = os.path.exists(os.path.join(self.repo_path, '.github', 'workflows'))
                 elif 'gitlab.com' in self.repo_url.lower():
                      workflow_files_exist = os.path.exists(os.path.join(self.repo_path, '.gitlab-ci.yml'))
                 elif 'bitbucket.org' in self.repo_url.lower():
                      workflow_files_exist = os.path.exists(os.path.join(self.repo_path, 'bitbucket-pipelines.yml'))

                 if not workflow_files_exist:
                      logger.warning("No changes to commit, and expected CI/CD configuration file seems missing.")
                 # Don't fail here, just inform the user.
                 return True # Still successful in the sense that there's nothing to do.


            # Commit changes
            commit_message = "feat: Add AI-generated CI/CD configuration" # Conventional commit style
            if added_to_gitignore:
                 commit_message += f"\n\n- Add {', '.join(added_to_gitignore)} to .gitignore"

            repo.index.commit(commit_message)
            logger.info(f"Committed changes with message: {commit_message}")

            # Push changes if token is available and repo uses HTTPS
            if self.git_token and self.repo_url.startswith("https://"):
                logger.info("Pushing changes to remote repository...")
                origin = repo.remote(name='origin')
                # Ensure the URL includes the token for the push
                # The URL used for cloning might already have it, but safer to set explicitly if needed
                # This depends on how clone_from handled the auth URL internally.
                # Let's try pushing to the default origin first. Git might cache creds or use helper.
                try:
                     push_info = origin.push()
                     # Check push_info for errors if needed
                     logger.info("Changes pushed successfully.")
                     for info in push_info:
                          if info.flags & info.ERROR:
                               logger.error(f"Error during push: {info.summary}")
                               # Fallback or specific error handling might be needed here
                          elif info.flags & info.REJECTED:
                               logger.error(f"Push rejected: {info.summary}. Hint: Fetch changes first?")
                               return False # Push failed definitely
                except GitCommandError as push_error:
                     logger.error(f"Git push failed: {push_error}")
                     logger.error(f"Stderr: {push_error.stderr}")
                     logger.error("Hint: Check repository write permissions for the token, or try pushing manually.")
                     return False # Indicate push failure

            elif not self.git_token and "@" in self.repo_url and ":" in self.repo_url:
                 logger.info("Repository uses SSH URL. Assuming SSH key authentication for push.")
                 logger.info("Attempting push using default SSH key setup...")
                 try:
                      origin = repo.remote(name='origin')
                      push_info = origin.push()
                      logger.info("Changes pushed successfully via SSH.")
                      for info in push_info: # Check flags as above
                          if info.flags & info.ERROR: logger.error(f"Error during push: {info.summary}")
                          elif info.flags & info.REJECTED: logger.error(f"Push rejected: {info.summary}")

                 except GitCommandError as push_error:
                      logger.error(f"Git push via SSH failed: {push_error}")
                      logger.error(f"Stderr: {push_error.stderr}")
                      logger.error("Hint: Ensure your SSH key is configured correctly and added to your Git provider.")
                      return False # Indicate push failure

            else:
                logger.info("No Git token provided for HTTPS repo or non-standard URL. Please push the committed changes manually.")
                # Provide manual push instructions
                print("\n--- Manual Push Instructions ---")
                print(f"1. Navigate to the temporary repository directory:")
                print(f"   cd {self.repo_path}")
                print(f"2. Push the commit:")
                print(f"   git push origin HEAD") # Push current branch to origin
                print("--------------------------------\n")


            return True
        except GitCommandError as e:
            logger.error(f"Git error during commit/push: {e}")
            logger.error(f"Stderr: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error committing changes: {e}", exc_info=True)
            return False


    # --- [ MODIFIED: generate_setup_instructions includes created resource details ] ---
    def generate_setup_instructions(self) -> str:
        """Generate setup instructions for the user, including created resource details."""
        instructions = ["# AI DevOps Setup Instructions\n"]

        # --- Git Repository Setup ---
        instructions.append("## 1. Repository & CI/CD Configuration")
        if self.commit_changes(): # Re-check commit/push status if needed, or use a flag set earlier
             instructions.append("✅ CI/CD configuration file has been generated and committed to your repository.")
             if self.git_token or ("@" in self.repo_url and ":" in self.repo_url and not self.git_token): # If token provided or SSH assumed
                  # Check if push actually happened if possible (e.g., commit_changes returns detailed status)
                  instructions.append("✅ Changes have been pushed to the remote repository.")
             else:
                  instructions.append("⚠️ **Action Required:** Manually push the commit:")
                  instructions.append("   ```bash")
                  instructions.append(f"   cd {self.repo_path}")
                  instructions.append("   git push origin HEAD") # Push current branch
                  instructions.append("   ```")
        else:
             instructions.append("❌ **Error:** Failed to commit or push CI/CD configuration.")
             instructions.append("   Please check the logs. You may need to manually add and commit the generated files in:")
             instructions.append(f"   `{self.repo_path}`")


        # --- Created Cloud Resource Details ---
        instructions.append("\n## 2. Created Cloud Resource")
        if not self.created_resource_details:
            instructions.append("ℹ️ No cloud resource was automatically created by this tool.")
            # Add instructions based on the *selected* config if not created
            res_type = self.resource_configuration.get('type', 'N/A')
            cloud = self.cloud_provider.upper()
            instructions.append(f"   You selected {cloud} {res_type} as the target.")
            instructions.append(f"   You will need to provision this resource manually or enhance the script.")
        else:
            details = self.created_resource_details
            res_type = details.get('type', 'Unknown Resource')
            instructions.append(f"✅ Successfully created/configured: **{res_type}**")
            for key, value in details.items():
                if key != 'type' and value: # Don't show 'type' again, hide empty values
                     # Mask sensitive parts if any were accidentally stored (shouldn't happen)
                     formatted_key = key.replace('_', ' ').title()
                     if 'key_private_path' in key and value != 'N/A':
                          instructions.append(f"   - **{formatted_key}:** `{value}`")
                          instructions.append(f"     🔒 **IMPORTANT:** Secure this private key file! Do not commit it.")
                          instructions.append(f"     Ensure permissions are restrictive (e.g., `chmod 600 {value}`)")
                     elif 'ssh_key_private_path' in key and value == 'N/A':
                           instructions.append(f"   - **{formatted_key}:** `{value}` (Key was not generated by this tool, assumed pre-existing)")
                     elif 'arn' in key:
                          instructions.append(f"   - **{formatted_key}:** `{value}`")
                     elif 'ip' in key or 'dns' in key or 'id' in key or 'name' in key:
                          instructions.append(f"   - **{formatted_key}:** `{value}`")
                     elif 'user' in key:
                           instructions.append(f"   - **{formatted_key}:** `{value}`")
                     # Add more formatting/filtering as needed

            # Add specific access instructions for VM types
            if details.get('ssh_key_private_path') and details.get('public_ip') and details.get('ssh_user') and details['ssh_key_private_path'] != 'N/A':
                 instructions.append("\n   **Accessing the VM via SSH:**")
                 instructions.append("   ```bash")
                 instructions.append(f"   chmod 600 \"{details['ssh_key_private_path']}\"") # Ensure permissions
                 instructions.append(f"   ssh -i \"{details['ssh_key_private_path']}\" {details['ssh_user']}@{details['public_ip']}")
                 instructions.append("   ```")


        # --- CI/CD Secret Setup ---
        instructions.append("\n## 3. CI/CD Secrets/Variables Setup")
        instructions.append("⚠️ **Action Required:** Configure the necessary secrets/variables in your CI/CD provider's settings.")

        repo_info = self.repo_url.lower()
        secret_location_guide = ""
        variable_type = "variable" # GitLab/Bitbucket often call them variables

        if 'github.com' in repo_info:
            secret_location_guide = "Go to your GitHub repository > Settings > Secrets and variables > Actions > Repository secrets."
            variable_type = "secret"
        elif 'gitlab.com' in repo_info:
            secret_location_guide = "Go to your GitLab repository > Settings > CI/CD > Variables (expand) > Add variable. Mark sensitive variables as 'Masked' and consider 'Protected' for production branches."
        elif 'bitbucket.org' in repo_info:
            secret_location_guide = "Go to your Bitbucket repository > Repository settings > Pipelines > Repository variables. Mark sensitive variables as 'Secured'."
        else: # Generic host
             secret_location_guide = "Refer to your specific Git hosting provider's documentation for setting CI/CD secrets/variables."

        instructions.append(f"   **Where to add:** {secret_location_guide}")
        instructions.append(f"   **Required {variable_type.upper()}S:**")

        # Add cloud-specific instructions based on the *credential type* used for CI/CD
        # Note: These secrets are for the CI/CD pipeline, NOT the resource access key (unless deploying via SSH)
        if self.cloud_provider == 'aws':
             instructions.append(f"   - `AWS_ACCESS_KEY_ID`: Your AWS Access Key ID for CI/CD.")
             instructions.append(f"   - `AWS_SECRET_ACCESS_KEY`: Your AWS Secret Access Key for CI/CD.")
             # instructions.append(f"   - `AWS_REGION`: (Optional if default is ok) The AWS region (e.g., {self.cloud_credentials.get('region', 'us-east-1')}).") # Often set in workflow directly
             if self.resource_configuration.get('type') == 'ec2':
                  # If deploying via SSH from pipeline, need the private key as a secret
                  if self.ssh_key_paths.get('private') and self.ssh_key_paths['private'] != 'N/A':
                       instructions.append(f"   - `EC2_SSH_PRIVATE_KEY`: The content of the private key file (`{self.ssh_key_paths['private']}`) generated for EC2 access.")
                       instructions.append(f"     (Copy the *entire* content, including `-----BEGIN...` and `-----END...` lines)")

        elif self.cloud_provider == 'azure':
             # Recommend OIDC/Federated Credentials over secrets if possible
             instructions.append(f"   - **Recommendation:** Use OpenID Connect (OIDC) / Workload Identity Federation if your CI/CD platform and Azure setup support it. This avoids storing long-lived secrets.")
             instructions.append(f"   - **If using Service Principal Secret:**")
             if 'github.com' in repo_info:
                   instructions.append(f"     - `AZURE_CREDENTIALS`: A JSON object containing your Service Principal details (clientId, clientSecret, subscriptionId, tenantId).")
                   instructions.append("       ```json")
                   instructions.append("       {")
                   instructions.append("         \"clientId\": \"YOUR_SP_CLIENT_ID\",")
                   instructions.append("         \"clientSecret\": \"YOUR_SP_SECRET\",")
                   instructions.append(f"         \"subscriptionId\": \"{self.cloud_credentials.get('subscription_id', 'YOUR_SUBSCRIPTION_ID')}\",")
                   instructions.append(f"         \"tenantId\": \"{self.cloud_credentials.get('tenant_id', 'YOUR_TENANT_ID')}\"")
                   instructions.append("       }")
                   instructions.append("       ```")
             else: # GitLab/Bitbucket often use separate variables
                   instructions.append(f"     - `AZURE_CLIENT_ID`: Your Service Principal Client ID.")
                   instructions.append(f"     - `AZURE_CLIENT_SECRET`: Your Service Principal Client Secret.")
                   instructions.append(f"     - `AZURE_TENANT_ID`: Your Azure Tenant ID.")
                   instructions.append(f"     - `AZURE_SUBSCRIPTION_ID`: Your Azure Subscription ID ({self.cloud_credentials.get('subscription_id', 'Not Set')}).")
             # Add SSH key secret if deploying to Azure VM via SSH
             if self.resource_configuration.get('type') == 'vm':
                  if self.ssh_key_paths.get('private') and self.ssh_key_paths['private'] != 'N/A':
                       instructions.append(f"   - `AZURE_VM_SSH_PRIVATE_KEY`: The content of the private key file (`{self.ssh_key_paths['private']}`) generated for VM access.")


        elif self.cloud_provider == 'gcp':
             instructions.append(f"   - **Recommendation:** Use Workload Identity Federation if your CI/CD platform and GCP setup support it.")
             instructions.append(f"   - **If using Service Account Key:**")
             instructions.append(f"     - `GCP_SA_KEY` (GitHub/GitLab) or `GCP_SA_KEY_BASE64` (Bitbucket): The JSON content of your GCP Service Account key file.")
             instructions.append(f"       (For Bitbucket, base64 encode the JSON content before pasting).")
             instructions.append(f"       (The key file used during setup was: {self.cloud_credentials.get('key_file', 'N/A - Used ADC?')})")
             # Project ID often set directly in workflow, but can be a variable too
             # instructions.append(f"   - `GCP_PROJECT_ID`: Your GCP Project ID ({self.cloud_credentials.get('project_id', 'Not Set')}).")


        # --- Next Steps ---
        instructions.append("\n## 4. Next Steps")
        instructions.append("1. **Review:** Carefully review the generated CI/CD configuration file(s) in your repository.")
        instructions.append("2. **Secure Keys:** Ensure any generated private SSH keys (`.pem` files) are stored securely and have correct file permissions (600). **Do not commit them to Git.**")
        instructions.append("3. **Set Secrets:** Configure the required secrets/variables in your CI/CD platform as detailed above.")
        instructions.append("4. **Push (If Needed):** If changes weren't pushed automatically, push the commit manually.")
        instructions.append("5. **Trigger Pipeline:** The pipeline should trigger automatically on the next push to the configured branch (e.g., main/master), or you can trigger it manually if supported (`workflow_dispatch` for GitHub Actions).")
        instructions.append("6. **Monitor:** Monitor the CI/CD pipeline execution in your Git provider's UI for success or errors.")
        instructions.append("7. **Refine:** Adjust the generated configuration and deployment scripts as needed for your specific application requirements.")

        return "\n".join(instructions)

    def cleanup(self):
        """Remove temporary directories, handling potential Windows errors."""

        def remove_readonly(func, path, exc_info):
            """
            Error handler for shutil.rmtree.

            If the error is due to an access error (read only file)
            it attempts to add write permission and then retries.

            If the error is for another reason it re-raises the error.

            Usage: shutil.rmtree(path, onerror=remove_readonly)
            """
            import stat
            # Check if file access error
            if not os.access(path, os.W_OK):
                # Try to change the mode to grant write access
                logger.debug(f"Attempting to change permissions for: {path}")
                try:
                     os.chmod(path, stat.S_IWRITE)
                     func(path) # Retry the function (e.g., os.remove)
                     logger.debug(f"Successfully removed after permission change: {path}")
                except Exception as e:
                     logger.error(f"Failed to remove {path} even after permission change: {e}")
                     # Re-raise the original exception or the new one if preferred
                     # raise # Re-raise the exception that occurred in func(path)
                     # Or raise the original exception:
                     exc_type, exc_value, tb = exc_info
                     raise exc_type(exc_value).with_traceback(tb)
            else:
                 # The error was not related to read-only permissions, re-raise it
                 exc_type, exc_value, tb = exc_info
                 logger.error(f"Cleanup error on {path} not related to read-only permissions: {exc_value}")
                 raise exc_type(exc_value).with_traceback(tb)


        if self.repo_path and os.path.isdir(self.repo_path):
            logger.info(f"Cleaning up temporary repository directory: {self.repo_path}")
            try:
                # Add the onerror handler to rmtree
                shutil.rmtree(self.repo_path, onerror=remove_readonly)
                logger.info(f"Successfully cleaned up {self.repo_path}")
                self.repo_path = None
            except FileNotFoundError:
                 logger.warning(f"Temporary directory {self.repo_path} not found during cleanup (already removed?).")
                 self.repo_path = None # Ensure it's cleared
            except OSError as e:
                logger.error(f"Error removing temporary directory {self.repo_path} even with handler: {e}")
                logger.error("You may need to manually delete the directory.")
            except Exception as e:
                 logger.error(f"Unexpected error during cleanup of {self.repo_path}: {e}")

        # Do NOT clean up generated .pem keys automatically, as the user needs them.

    def run(self):
        """Run the entire workflow"""
        try:
            if not self.collect_git_credentials():
                return "Failed to collect Git credentials."

            if not self.access_repository():
                # Cleanup already cloned repo if cloning failed partially but dir was created
                self.cleanup()
                return "Failed to access repository. Check URL, permissions, and network."

            if not self.collect_cloud_credentials():
                 self.cleanup()
                 return "Failed to collect cloud credentials."

            # Renamed step: Configure *and Create*
            if not self.configure_and_create_cloud_resource():
                 self.cleanup()
                 # Provide more context if resource details exist but maybe failed later
                 if self.created_resource_details:
                      return f"Failed during cloud resource configuration or creation after initial steps. Details: {self.created_resource_details}"
                 else:
                      return "Failed to configure or create cloud resource. Check credentials and permissions."


            if not self.generate_cicd_config():
                 # Resource might be created, but pipeline gen failed. Don't clean up resource, but maybe warn.
                 logger.warning("Cloud resource may have been created, but CI/CD generation failed.")
                 self.cleanup() # Clean up repo clone
                 return "Failed to generate CI/CD configuration."

            # Commit the generated CI/CD files
            if not self.commit_changes():
                 # Don't clean up repo yet, user might want to fix manually
                 logger.warning("Failed to commit or push changes. Please check the temporary repo directory.")
                 # Keep repo path available for manual push instruction
                 # self.repo_path contains the path

            # Generate final instructions including resource details and manual steps
            setup_instructions = self.generate_setup_instructions()

            # Optionally clean up the local repo clone *after* instructions are generated
            # self.cleanup() # Or leave it for the user as per instructions

            return setup_instructions

        except Exception as e:
             logger.error(f"An unexpected error occurred in the main workflow: {e}", exc_info=True)
             self.cleanup() # Attempt cleanup on any major failure
             return f"An unexpected error occurred: {e}"
        finally:
             # Ensure cleanup happens if not done explicitly elsewhere, but maybe not if user needs the repo
             # Let's leave the repo if commit failed, otherwise clean up.
             if self.repo_path and os.path.isdir(self.repo_path) and not "Failed to commit or push changes" in locals().get("setup_instructions", ""):
                  # self.cleanup() # Decided against auto-cleanup here, let user manage the temp dir based on output.
                  logger.info(f"Workflow finished. Temporary repo location (if needed): {self.repo_path}")
                  pass # Keep the repo


# --- [ main function remains the same ] ---
def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='AI DevOps Tool - Automatically configure CI/CD and provision basic cloud resources.')
    # Add arguments for non-interactive mode later if needed
    # parser.add_argument('--repo-url', help='Git repository URL')
    # parser.add_argument('--cloud-provider', choices=['aws', 'azure', 'gcp'], help='Target cloud provider')
    # ... other args
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging (DEBUG level)')
    parser.add_argument('--cleanup-repo', action='store_true', help='Force cleanup of the temporary repo directory after execution (even on commit failure)')


    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        # Potentially enable debug logging for specific libraries if needed
        # logging.getLogger('boto3').setLevel(logging.DEBUG)
        # logging.getLogger('botocore').setLevel(logging.DEBUG)
        # logging.getLogger('azure').setLevel(logging.DEBUG)
        # logging.getLogger('google').setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")


    print("="*80)
    print("🤖 Welcome to AI DevOps Automation Tool! 🤖")
    print("This tool will help you set up a basic CI/CD pipeline and provision")
    print("an initial cloud resource for your codebase.")
    print("="*80)

    automator = AIDevOpsAutomator()
    result = automator.run() # Now returns instructions or error message

    print("\n")
    print("="*80)
    print("✨ Automation Result ✨")
    print("="*80)
    print(result) # Print the generated instructions or error message
    print("="*80)

    # Handle cleanup based on flag or success/failure
    if args.cleanup_repo:
         logger.info("Force cleanup requested.")
         automator.cleanup()
    elif automator.repo_path and os.path.isdir(automator.repo_path):
         # If commit/push failed, the instructions advise manual steps from the repo path
         if "Failed to commit or push changes" in result:
              logger.warning(f"Commit/push failed. The temporary repository is left at: {automator.repo_path}")
              logger.warning("Please follow the manual push instructions above and delete the directory when done.")
         # If successful, but user didn't force cleanup, maybe ask?
         # else:
         #      cleanup_choice = input(f"Delete temporary repository directory ({automator.repo_path})? (y/N): ").lower()
         #      if cleanup_choice == 'y':
         #           automator.cleanup()
         else: # Successful run, default to cleaning up unless --no-cleanup or similar flag exists
              logger.info("Cleaning up temporary repository directory...")
              automator.cleanup()


if __name__ == "__main__":
    # Ensure necessary external libraries are installed
    try:
         import git
         import yaml
         import boto3
         import azure.identity
         import azure.mgmt.resource
         import google.cloud.resourcemanager_v3 # Keep core import
         import cryptography
         # Add compute/network etc imports here if check needed
    except ImportError as e:
         print(f"Error: Missing required Python package: {e.name}")
         print("Please install the necessary libraries. You might need:")
         print("  pip install GitPython PyYAML boto3 azure-identity azure-mgmt-resource azure-mgmt-compute azure-mgmt-network google-cloud-compute google-cloud-run google-cloud-functions google-auth google-api-python-client cryptography")
         exit(1)

    main()