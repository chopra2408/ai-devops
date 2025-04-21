# --- START OF FILE llm.py ---
import os
import argparse
import getpass
import yaml
import tempfile
import json
from git import Repo, GitCommandError
from typing import List, Optional, Tuple
import logging
import shutil
import stat
import time

# --- Cloud SDK Imports ---
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import azure.identity
import azure.mgmt.resource
import azure.mgmt.compute
import azure.mgmt.network
from azure.core.exceptions import ResourceNotFoundError as AzureResourceNotFoundError
# Correct Google imports
from google.cloud import compute_v1
from google.oauth2 import service_account
import google.auth # Explicitly import google.auth
import google.auth.exceptions # Import exceptions submodule
from google.api_core import exceptions as google_exceptions
# Cryptography
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

# --- LLM Import ---
import openai
try:
    from github import Github, GithubException, UnknownObjectException
except ImportError:
    # We'll handle this later in the library check
    Github = None
    
try:
    import nacl
    from nacl.public import SealedBox, PublicKey
    from nacl.encoding import Base64Encoder
except ImportError:
    nacl = None

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ai-devops')

# --- Helper Function for SSH Key (Corrected version) ---
def generate_ssh_key_pair(key_filename_base="ai-devops-key"):
    # ... (Use the full corrected implementation from the previous response) ...
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
            with open(private_key_path, "rb") as key_file:
                private_key = crypto_serialization.load_pem_private_key(
                    key_file.read(), password=None, backend=crypto_default_backend()
                )
            if os.path.exists(public_key_path):
                logger.info(f"Found existing public key: {public_key_path}")
                with open(public_key_path, "r") as f:
                    public_key_content = f.read()
            else:
                logger.warning(f"Public key {public_key_path} missing. Regenerating from private key.")
                public_key = private_key.public_key()
                public_key_ssh = public_key.public_bytes(
                    crypto_serialization.Encoding.OpenSSH, crypto_serialization.PublicFormat.OpenSSH
                )
                with open(public_key_path, "wb") as f:
                    f.write(public_key_ssh)
                logger.info(f"Regenerated and saved public key to: {public_key_path}")
                public_key_content = public_key_ssh.decode('utf-8')
        except Exception as e:
             logger.error(f"Error loading/regenerating from existing private key {private_key_path}: {e}", exc_info=True)
             logger.error("Recommendation: Delete the existing .pem and .pub files and rerun the script.")
             return None, None, None
    else:
        logger.info(f"Generating new SSH key pair: {key_filename_base}")
        try:
             key = rsa.generate_private_key(
                 backend=crypto_default_backend(), public_exponent=65537, key_size=2048
             )
             private_key_pem = key.private_bytes(
                 crypto_serialization.Encoding.PEM, crypto_serialization.PrivateFormat.TraditionalOpenSSL, crypto_serialization.NoEncryption()
             )
             public_key = key.public_key()
             public_key_ssh = public_key.public_bytes(
                 crypto_serialization.Encoding.OpenSSH, crypto_serialization.PublicFormat.OpenSSH
             )
             with open(private_key_path, "wb") as f: f.write(private_key_pem)
             try:
                  os.chmod(private_key_path, stat.S_IREAD | stat.S_IWRITE)
                  logger.info(f"Private key saved to: {private_key_path} (Permissions set)")
             except OSError:
                   logger.warning(f"Private key saved to: {private_key_path} (Could not set restrictive permissions)")
             with open(public_key_path, "wb") as f: f.write(public_key_ssh)
             logger.info(f"Public key saved to: {public_key_path}")
             public_key_content = public_key_ssh.decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to generate new key pair: {e}", exc_info=True)
            return None, None, None

    if not public_key_content:
         logger.error("Failed to obtain public key content.")
         return None, None, None

    return private_key_path, public_key_content, key_filename_base

# --- Error handler for shutil.rmtree ---
def remove_readonly(func, path, exc_info):
    """
    Error handler for shutil.rmtree. Tries to fix permissions on Windows.
    """
    # Check if file access error
    if not os.access(path, os.W_OK):
        logger.debug(f"Attempting to change permissions for: {path}")
        try:
             os.chmod(path, stat.S_IWRITE)
             func(path) # Retry the function (e.g., os.remove)
             logger.debug(f"Successfully removed after permission change: {path}")
        except Exception as e:
             logger.error(f"Failed to remove {path} even after permission change: {e}")
             exc_type, exc_value, tb = exc_info
             raise exc_type(exc_value).with_traceback(tb)
    else:
         exc_type, exc_value, tb = exc_info
         logger.error(f"Cleanup error on {path} not related to read-only permissions: {exc_value}")
         raise exc_type(exc_value).with_traceback(tb)


class AIDevOpsAutomator:
    def __init__(self):
        self.repo_url = None
        self.git_token = None
        self.repo_path = None
        self.cloud_provider = None
        self.cloud_credentials = {}
        self.detected_stack = None
        self.resource_configuration = {}
        self.created_resource_details = {}
        self.selected_resource_details = {}
        self.ssh_key_paths = {}
        self.ci_platform = None
        self.openai_client = None
        self.repo_path = None  
        self.github_client = None  
        self.is_github_repo = False  
        self.repo_object = None
        self.ssh_key_secret_set = False

        # Initialize OpenAI Client
        try:
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key:
                logger.warning("OPENAI_API_KEY environment variable not set. LLM features will be disabled.")
            else:
                # Ensure openai library was imported successfully before using it
                if 'openai' in globals():
                     self.openai_client = openai.OpenAI(api_key=api_key)
                     logger.info("OpenAI client initialized.")
                else:
                     logger.error("OpenAI library import failed earlier. Cannot initialize client.")

        except ImportError:
             logger.warning("OpenAI library not found (`pip install openai`). LLM features disabled.")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            self.openai_client = None

    # --- Git/Stack Methods (Assumed Correct from Previous Fixes) ---
    def collect_git_credentials(self) -> bool:
        logger.info("Collecting Git credentials...")
        self.repo_url = input("Enter Git repository URL: ")
        if not self.repo_url:
            logger.error("Repository URL cannot be empty")
            return False

        # Check if it's a likely GitHub HTTPS URL for API interaction
        if self.repo_url.startswith("https://github.com/"):
            self.is_github_repo = True
            logger.info("GitHub repository detected. Will attempt API interaction.")
            self.git_token = getpass.getpass(
                "Enter GitHub Personal Access Token (PAT) with 'repo' scope (required for API access): "
            )
            if not self.git_token:
                logger.error("GitHub token is required for API-based operations.")
                return False
            # Try to authenticate early
            try:
                self.github_client = Github(self.git_token)
                user = self.github_client.get_user()
                logger.info(f"Successfully authenticated with GitHub API as user: {user.login}")
            except GithubException as e:
                logger.error(f"GitHub API authentication failed: {e.status} - {e.data.get('message', 'Unknown error')}")
                logger.error("Please ensure your token is valid and has the 'repo' scope.")
                return False
        else:
            # Fallback to existing logic for non-GitHub or SSH URLs
            self.is_github_repo = False
            logger.warning("Non-GitHub HTTPS URL detected or SSH URL used. Falling back to local clone method.")
            # ... (Keep original logic for token prompt based on URL type) ...
            is_likely_private = self.repo_url.startswith("https://") and \
                                any(host in self.repo_url for host in ["gitlab.com", "bitbucket.org", "dev.azure.com"])
            is_ssh_format = "@" in self.repo_url and ":" in self.repo_url
            if is_likely_private or is_ssh_format:
                use_token = input("Is this a private repository requiring authentication (token/password/SSH Key)? (y/N): ").lower() == 'y'
                if use_token:
                    token_input = getpass.getpass("Enter Git access token/password (for clone, input hidden): ")
                    if token_input: self.git_token = token_input
                    else:
                        logger.error("Git token/password is required for private repositories if specified for cloning.")
                        return False
                elif is_ssh_format: logger.info("Assuming SSH key authentication for SSH URL format (requires local clone).")
                else: logger.info("Proceeding without token for potentially public repository (requires local clone).")
            else: logger.info("Assuming public repository or anonymous access (requires local clone).")

        return True
    
    def _get_github_repo_object(self) -> bool:
        """Gets the PyGithub Repository object."""
        if not self.is_github_repo or not self.github_client:
            return False # Should not happen if collect_git_credentials passed

        repo_full_name = self.repo_url.replace("https://github.com/", "").replace(".git", "")
        try:
            self.repo_object = self.github_client.get_repo(repo_full_name)
            logger.info(f"Successfully obtained GitHub repository object for: {repo_full_name}")
            return True
        except UnknownObjectException:
            logger.error(f"Repository '{repo_full_name}' not found or token lacks permission.")
            return False
        except GithubException as e:
            logger.error(f"Failed to get repository object: {e.status} - {e.data.get('message', 'Unknown error')}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error getting GitHub repo object: {e}", exc_info=True)
            return False

    def access_repository_and_detect_stack(self) -> bool:
        """
        Accesses repository files (via API for GitHub, clone otherwise)
        and detects the tech stack.
        """
        if self.is_github_repo:
            if not self._get_github_repo_object():
                return False
            return self._detect_stack_via_api()
        else:
            # Use the original clone-based method
            logger.info("Using local clone method for stack detection.")
            return self._access_repository_via_clone()
        
    def _detect_stack_via_api(self) -> bool:
        """Detects stack by listing root files using GitHub API."""
        logger.info("Detecting technology stack via GitHub API...")
        if not self.repo_object:
            logger.error("GitHub repository object not available.")
            return False
        try:
            contents = self.repo_object.get_contents("") # Get root contents
            files = [item.name for item in contents if item.type == 'file']
            logger.debug(f"Files found in root via API: {files}")

            stack = self._determine_stack_from_files(files) # Use helper
            self.detected_stack = stack
            logger.info(f"Detected technology stack via API: {self.detected_stack}")
            return True

        except UnknownObjectException:
            logger.warning("Repository root seems empty or inaccessible via API.")
            self.detected_stack = 'unknown'
            return True # Allow proceeding, maybe user knows stack
        except GithubException as e:
            logger.error(f"GitHub API error listing files: {e.status} - {e.data.get('message', 'Error')}")
            return False
        except Exception as e:
            logger.error(f"Error detecting stack via API: {e}", exc_info=True)
            self.detected_stack = 'unknown'
            return False
        
    def _access_repository_via_clone(self) -> bool:
        logger.info(f"Accessing repository via local clone: {self.repo_url}")
        try:
            temp_dir = tempfile.mkdtemp(prefix="ai-devops-repo-")
            self.repo_path = temp_dir
            logger.info(f"Cloning repository into temporary directory: {self.repo_path}")
            # ... (Keep original clone logic using self.repo_url and self.git_token) ...
            clone_url = self.repo_url
            env = os.environ.copy()
            if self.git_token and self.repo_url.startswith("https://"):
                # ... (logic for authenticated HTTPS clone) ...
                if "@" in self.repo_url.split("://")[1]:
                    proto, rest = self.repo_url.split("://")
                    clone_url = f"{proto}://oauth2:{self.git_token}@{rest.split('@', 1)[-1]}"
                else:
                    clone_url = self.repo_url.replace('https://', f'https://oauth2:{self.git_token}@')
                logger.debug(f"Using authenticated URL for clone: {clone_url.replace(self.git_token, '***TOKEN***')}")
            elif not self.git_token and "@" in self.repo_url and ":" in self.repo_url:
                logger.info("Attempting clone using SSH protocol. Ensure your SSH key is configured.")

            Repo.clone_from(clone_url, self.repo_path, env=env, depth=1) # Use shallow clone
            logger.info(f"Repository cloned successfully (shallow) to {self.repo_path}")

            # Detect stack from local files
            if not self._detect_stack_from_local_dir(): # Use helper
                return False # Detection failed

            return True
        except GitCommandError as e:
            logger.error(f"Git error during clone: {e.stderr}")
            if self.repo_path: self.cleanup() # Cleanup on clone failure
            return False
        except Exception as e:
            logger.error(f"Unexpected error accessing repository via clone: {e}", exc_info=True)
            if self.repo_path: self.cleanup() # Cleanup on clone failure
            return False   
        
    def _detect_stack_from_local_dir(self) -> bool:
        """Detects stack based on files in self.repo_path."""
        logger.info("Detecting technology stack from local directory...")
        if not self.repo_path or not os.path.isdir(self.repo_path):
            logger.error("Local repository path is not valid for stack detection.")
            self.detected_stack = 'unknown'
            return False
        try:
            files = os.listdir(self.repo_path)
            stack = self._determine_stack_from_files(files) # Use helper
            self.detected_stack = stack
            logger.info(f"Detected technology stack from local files: {self.detected_stack}")
            return True
        except Exception as e:
            logger.error(f"Error detecting technology stack locally: {e}", exc_info=True)
            self.detected_stack = 'unknown'
            return False
        
    def _determine_stack_from_files(self, files: List[str]) -> str:
        """Helper function to determine stack from a list of filenames."""
        stack = None
        # ... (Keep the original detection logic based on filenames) ...
        if 'package.json' in files: stack = 'nodejs'
        elif 'requirements.txt' in files or 'setup.py' in files or 'Pipfile' in files or 'pyproject.toml' in files: stack = 'python'
        elif 'pom.xml' in files or 'build.gradle' in files or 'build.gradle.kts' in files: stack = 'java'
        elif 'go.mod' in files: stack = 'golang'
        elif any(f.endswith('.csproj') for f in files) or 'project.json' in files: stack = 'dotnet'
        elif 'composer.json' in files: stack = 'php'
        elif 'Cargo.toml' in files: stack = 'rust'

        # Dockerfile check last
        if 'Dockerfile' in files and stack is None:
            stack = 'docker'
        elif 'Dockerfile' in files and stack is not None:
            logger.info(f"Dockerfile found, but stack already detected as {stack}. Keeping primary stack.")

        if stack is None:
            logger.info("No primary stack file found. Stack is unknown.")
            stack = 'unknown'
        return stack

    # --- Cloud Credential Collection (Assumed Correct from Previous Fixes) ---
    def collect_cloud_credentials(self) -> bool:
        logger.info("Collecting cloud provider credentials...")
        providers = ['aws', 'azure', 'gcp']
        print("\nAvailable cloud providers:")
        for i, provider in enumerate(providers, 1): print(f"{i}. {provider.upper()}")
        choice = input(f"Select cloud provider (1-{len(providers)}): ")
        try:
            index = int(choice) - 1
            if 0 <= index < len(providers): self.cloud_provider = providers[index]
            else: raise ValueError("Invalid selection number")
        except ValueError as e:
            logger.error(f"Invalid input: {e}")
            return False
        logger.info(f"Selected cloud provider: {self.cloud_provider.upper()}")
        if self.cloud_provider == 'aws': return self._collect_aws_credentials()
        elif self.cloud_provider == 'azure': return self._collect_azure_credentials()
        elif self.cloud_provider == 'gcp': return self._collect_gcp_credentials()
        return False

    def _collect_aws_credentials(self) -> bool:
        print("\nAWS Credential Options:")
        print("1. Use AWS CLI profile")
        print("2. Enter Access Key and Secret Key")
        print("3. Assume Role")
        choice = input("Select option (1-3): ")
        if choice == '1':
             profile = input("Enter AWS profile name [default]: ") or "default"
             region = input(f"Enter AWS region (optional, detected later): ") or None
             self.cloud_credentials = {'type': 'profile', 'profile': profile, 'region': region}
        elif choice == '2':
             access_key = input("Enter AWS Access Key ID: ")
             secret_key = getpass.getpass("Enter AWS Secret Access Key: ")
             region = input("Enter AWS region [us-east-1]: ") or "us-east-1"
             if not access_key or not secret_key: logger.error("Keys cannot be empty"); return False
             self.cloud_credentials = {'type': 'keys', 'access_key': access_key, 'secret_key': secret_key, 'region': region}
        elif choice == '3':
             # Simplified Assume Role collection
             base_choice = input("Use profile (1) or keys (2) for base credentials? ")
             base_creds = {}
             if base_choice == '1': base_creds = {'base_type': 'profile', 'base_profile': input("Base profile [default]: ") or "default"}
             elif base_choice == '2':
                  akey = input("Base Key ID: "); skey = getpass.getpass("Base Secret Key: ")
                  if not akey or not skey: logger.error("Base keys cannot be empty"); return False
                  base_creds = {'base_type': 'keys', 'base_access_key': akey, 'base_secret_key': skey}
             else: logger.error("Invalid base choice"); return False
             role_arn = input("Role ARN to assume: ")
             if not role_arn: logger.error("Role ARN cannot be empty"); return False
             session_name = input("Role session name [ai-devops-session]: ") or "ai-devops-session"
             region = input(f"Region for assumed role session [us-east-1]: ") or "us-east-1"
             self.cloud_credentials = {'type': 'assume_role', 'role_arn': role_arn, 'session_name': session_name, 'region': region, **base_creds}
        else: logger.error("Invalid option"); return False
        return True

    def _collect_azure_credentials(self) -> bool:
        print("\nAzure Credential Options:")
        print("1. Use Azure CLI Login")
        print("2. Enter Service Principal details")
        print("3. Use Managed Identity")
        choice = input("Select option (1-3): ")
        sub_id = input("Enter Azure Subscription ID (required): ")
        if not sub_id: logger.error("Subscription ID required"); return False
        if choice == '1': self.cloud_credentials = {'type': 'cli', 'subscription_id': sub_id}
        elif choice == '2':
             tenant_id = input("Tenant ID: "); client_id = input("Client ID: "); client_secret = getpass.getpass("Client Secret: ")
             if not all([tenant_id, client_id, client_secret]): logger.error("SP details cannot be empty"); return False
             self.cloud_credentials = {'type': 'service_principal', 'tenant_id': tenant_id, 'client_id': client_id, 'client_secret': client_secret, 'subscription_id': sub_id}
        elif choice == '3':
             msi_client_id = input("User-Assigned Managed Identity Client ID (optional): ")
             self.cloud_credentials = {'type': 'managed_identity', 'subscription_id': sub_id}
             if msi_client_id: self.cloud_credentials['msi_client_id'] = msi_client_id
        else: logger.error("Invalid option"); return False
        return True

    def _collect_gcp_credentials(self) -> bool:
        print("\nGCP Credential Options:")
        print("1. Use Application Default Credentials (ADC)")
        print("2. Enter path to service account JSON key file")
        choice = input("Select option (1-2): ")
        project_id = input("Enter GCP Project ID (required): ")
        if not project_id: logger.error("Project ID required"); return False
        if choice == '1':
             self.cloud_credentials = {'type': 'application_default', 'project_id': project_id}
        elif choice == '2':
             key_file = input("Path to GCP service account key file (.json): ")
             if not os.path.exists(key_file): logger.error(f"Key file not found: {key_file}"); return False
             # Optional: Validate key file project ID against user input
             self.cloud_credentials = {'type': 'service_account', 'key_file': key_file, 'project_id': project_id}
        else: logger.error("Invalid option"); return False
        return True


    # --- Cloud Client/Session Helpers (RESTORED FULL IMPLEMENTATION) ---
    def _get_aws_session(self) -> Optional[boto3.Session]:
        """Initializes and returns a boto3 Session based on stored credentials."""
        creds = self.cloud_credentials
        session_params = {}
        region = creds.get('region')
        if not region and creds.get('type') == 'profile':
             try: region = boto3.Session(profile_name=creds.get('profile')).region_name
             except Exception: pass
        if region: session_params['region_name'] = region
        elif boto3.Session().region_name: session_params['region_name'] = boto3.Session().region_name
        else: session_params['region_name'] = 'us-east-1'; logger.warning("Defaulting AWS region to us-east-1")
        self.cloud_credentials['region'] = session_params['region_name']

        try:
            if creds.get('type') == 'profile':
                session_params['profile_name'] = creds.get('profile')
                logger.info(f"Using AWS profile: {creds.get('profile')} in region {session_params['region_name']}")
                return boto3.Session(**session_params)
            elif creds.get('type') == 'keys':
                logger.info(f"Using AWS access keys in region {session_params['region_name']}")
                session_params['aws_access_key_id'] = creds.get('access_key')
                session_params['aws_secret_access_key'] = creds.get('secret_key')
                return boto3.Session(**session_params)
            elif creds.get('type') == 'assume_role':
                 logger.info(f"Attempting to assume role: {creds.get('role_arn')}")
                 base_session_params = {'region_name': session_params['region_name']}
                 if creds.get('base_type') == 'profile':
                      base_session_params['profile_name'] = creds.get('base_profile')
                      base_session = boto3.Session(**base_session_params)
                 elif creds.get('base_type') == 'keys':
                      base_session_params['aws_access_key_id'] = creds.get('base_access_key')
                      base_session_params['aws_secret_access_key'] = creds.get('base_secret_key')
                      base_session = boto3.Session(**base_session_params)
                 else: logger.error("Invalid base credential type for assume role."); return None
                 sts_client = base_session.client('sts')
                 assumed_role_object = sts_client.assume_role(
                      RoleArn=creds.get('role_arn'), RoleSessionName=creds.get('session_name')
                 )
                 assumed_creds = assumed_role_object['Credentials']
                 logger.info(f"Successfully assumed role {creds.get('role_arn')}")
                 return boto3.Session(
                      aws_access_key_id=assumed_creds['AccessKeyId'],
                      aws_secret_access_key=assumed_creds['SecretAccessKey'],
                      aws_session_token=assumed_creds['SessionToken'],
                      region_name=session_params['region_name']
                 )
            else: logger.error(f"Unsupported AWS credential type: {creds.get('type')}"); return None
        except (ClientError, NoCredentialsError) as e: logger.error(f"AWS credential error: {e}"); return None
        except Exception as e: logger.error(f"Failed to create AWS session: {e}"); return None

    def _get_azure_credential(self) -> Optional[azure.identity.ChainedTokenCredential]:
         """Gets the appropriate Azure credential object."""
         creds = self.cloud_credentials
         credential_list = []
         try:
              cred_type = creds.get('type')
              if cred_type == 'cli':
                   logger.info("Using Azure CLI credential.")
                   credential_list.append(azure.identity.AzureCliCredential())
              elif cred_type == 'service_principal':
                   logger.info("Using Azure Service Principal credential.")
                   credential_list.append(azure.identity.ClientSecretCredential(
                        tenant_id=creds.get('tenant_id'),
                        client_id=creds.get('client_id'),
                        client_secret=creds.get('client_secret')
                   ))
              elif cred_type == 'managed_identity':
                   msi_client_id = creds.get('msi_client_id')
                   if msi_client_id:
                        logger.info(f"Using User-Assigned Managed Identity (ClientID: {msi_client_id}).")
                        credential_list.append(azure.identity.ManagedIdentityCredential(client_id=msi_client_id))
                   else:
                        logger.info("Using System-Assigned Managed Identity.")
                        credential_list.append(azure.identity.ManagedIdentityCredential())
              else: logger.error(f"Unsupported Azure credential type: {cred_type}"); return None

              if credential_list: return azure.identity.ChainedTokenCredential(*credential_list)
              else: return None
         except ImportError: logger.error("Azure identity library not found."); return None
         except Exception as e: logger.error(f"Failed to create Azure credential object: {e}"); return None

    def _get_gcp_credential(self) -> Optional[Tuple[object, str]]:
         """Gets GCP credentials object and project ID."""
         creds = self.cloud_credentials
         project_id = creds.get('project_id')
         if not project_id: logger.error("GCP Project ID is missing."); return None, None
         try:
              cred_type = creds.get('type')
              if cred_type == 'application_default':
                   logger.info(f"Using GCP Application Default Credentials for project {project_id}.")
                   # Use google.auth here
                   credentials, discovered_project_id = google.auth.default()
                   # ADC might discover a different project, ensure consistency or warn
                   if discovered_project_id and discovered_project_id != project_id:
                       logger.warning(f"ADC discovered project '{discovered_project_id}', using configured '{project_id}'.")
                   # Explicitly associate project_id for quota and client libraries if needed
                   scoped_credentials = credentials.with_quota_project(project_id)
                   return scoped_credentials, project_id
              elif cred_type == 'service_account':
                   key_file = creds.get('key_file')
                   logger.info(f"Using GCP Service Account key file: {key_file} for project {project_id}.")
                   credentials = service_account.Credentials.from_service_account_file(key_file)
                   scoped_credentials = credentials.with_quota_project(project_id)
                   return scoped_credentials, project_id
              else: logger.error(f"Unsupported GCP credential type: {cred_type}"); return None, None
         # Correct exception types for google.auth
         except (google.auth.exceptions.DefaultCredentialsError, google.auth.exceptions.RefreshError, FileNotFoundError) as e:
              logger.error(f"GCP credential error: {e}"); return None, None
         except Exception as e: logger.error(f"Failed to create GCP credentials: {e}"); return None, None


    # --- Resource Configuration (Existing/New Selection) ---
    def configure_cloud_resource(self) -> bool: # Renamed from configure_and_create...
        """Configure cloud deployment target: allow selecting existing or creating new."""
        logger.info(f"Configuring deployment target on {self.cloud_provider.upper()}...")
        try:
            if self.cloud_provider == 'aws': return self._configure_aws_resource()
            elif self.cloud_provider == 'azure': return self._configure_azure_resource()
            elif self.cloud_provider == 'gcp': return self._configure_gcp_resource()
            logger.error(f"Cloud provider {self.cloud_provider} configuration not implemented."); return False
        except (ClientError, NoCredentialsError, azure.core.exceptions.ClientAuthenticationError, google.auth.exceptions.GoogleAuthError) as e:
            logger.error(f"Authentication or Credential Error during configuration: {e}"); return False
        except Exception as e:
            logger.error(f"Unexpected error during cloud resource configuration: {e}", exc_info=True); return False

    # --- AWS Configuration ---
    def _configure_aws_resource(self) -> bool:
        session = self._get_aws_session()
        if not session: return False
        # Store region in config for later use if needed
        self.resource_configuration['region'] = session.region_name
        logger.info(f"Configuring AWS resource target in region: {session.region_name}...")
        # ... (rest of the method: target type selection, calling _configure_or_select_...) ...
        ec2 = session.client('ec2')
        ecs = session.client('ecs')
        lambda_client = session.client('lambda')
        print("\nAvailable AWS deployment targets:\n1. EC2\n2. ECS/Fargate\n3. Lambda")
        choice = input("Select target type (1-3): ")
        if choice == '1': self.resource_configuration['type'] = 'ec2'; return self._configure_or_select_aws_ec2(ec2)
        elif choice == '2': self.resource_configuration['type'] = 'ecs'; return self._configure_or_select_aws_ecs_cluster(ecs)
        elif choice == '3': self.resource_configuration['type'] = 'lambda'; return self._configure_or_select_aws_lambda(lambda_client, session.client('iam'))
        else: logger.error("Invalid type"); return False


    def _configure_or_select_aws_ec2(self, ec2_client) -> bool:
        # ... (Implementation is mostly correct, ensure keys are handled) ...
        existing_instances = []
        try:
            paginator = ec2_client.get_paginator('describe_instances')
            pages = paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]) # Simplified filter
            for page in pages:
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
                        # Only add if it has an ID, sanity check
                        if instance.get('InstanceId'):
                             existing_instances.append({
                                 'id': instance['InstanceId'], 'name': instance_name, 'type': instance.get('InstanceType'),
                                 'state': instance.get('State', {}).get('Name'), 'ip': instance.get('PublicIpAddress'),
                                 'key_name': instance.get('KeyName'), 'ssh_user': 'ec2-user' # Assumption
                             })
        except ClientError as e: logger.warning(f"Could not list existing EC2 instances: {e}")

        print("\nEC2 Instance Options:\n0. Create NEW EC2 Instance")
        if existing_instances:
            print("--- Existing Instances ---")
            for i, inst in enumerate(existing_instances, 1): print(f"{i}. {inst.get('name','N/A')} ({inst.get('id')}) - Type: {inst.get('type')}, State: {inst.get('state')}, IP: {inst.get('ip')}")
            print("------------------------")
        choice = input(f"Select option (0-{len(existing_instances)}): ")
        try:
            choice_idx = int(choice)
            if choice_idx == 0:
                logger.info("Configuring NEW EC2 instance...")
                instance_types = ['t2.micro', 't3.micro', 't3.small', 'm5.large'] # Example types
                print("\nSelect NEW EC2 instance type:")
                for i, itype in enumerate(instance_types, 1): print(f"{i}. {itype}")
                type_choice = input(f"Instance type (1-{len(instance_types)}) [default: {instance_types[0]}]: ")
                idx = int(type_choice) - 1 if type_choice.isdigit() else -1
                self.resource_configuration['instance_type'] = instance_types[idx] if 0 <= idx < len(instance_types) else instance_types[0]
                self.resource_configuration['create_new'] = True
                return True
            elif 1 <= choice_idx <= len(existing_instances):
                selected_instance = existing_instances[choice_idx - 1]
                logger.info(f"Selected existing EC2 instance: {selected_instance.get('id')}")
                self.selected_resource_details = {**selected_instance, 'type': 'AWS EC2 Instance (Existing)'}
                logger.warning(f"Selected existing instance with key pair name '{selected_instance.get('key_name')}'. Ensure you have the private key.")
                self.resource_configuration['create_new'] = False
                self.resource_configuration['instance_type'] = selected_instance.get('type') # Store for info
                self.ssh_key_paths = {} # Clear generated key paths
                return True
            else: logger.error("Invalid selection."); return False
        except ValueError: logger.error("Invalid input."); return False

    def _configure_or_select_aws_ecs_cluster(self, ecs_client) -> bool:
         # ... (Implementation looks okay, ensure keys are handled) ...
         existing_clusters = []
         try:
             response = ecs_client.list_clusters()
             if response.get('clusterArns'):
                  desc_response = ecs_client.describe_clusters(clusters=response['clusterArns'])
                  for cluster in desc_response.get('clusters', []):
                       if cluster.get('clusterName'): # Ensure name exists
                           existing_clusters.append({'name': cluster['clusterName'], 'arn': cluster.get('clusterArn'), 'status': cluster.get('status')})
         except ClientError as e: logger.warning(f"Could not list existing ECS clusters: {e}")

         print("\nECS Cluster Options:\n0. Create NEW ECS Cluster")
         if existing_clusters:
             print("--- Existing Clusters ---")
             for i, cluster in enumerate(existing_clusters, 1): print(f"{i}. {cluster.get('name')} ({cluster.get('status')})")
             print("------------------------")
         choice = input(f"Select option (0-{len(existing_clusters)}): ")
         try:
             choice_idx = int(choice)
             if choice_idx == 0:
                 logger.info("Configuring NEW ECS cluster...")
                 self.resource_configuration['cluster_name'] = input("Enter name for NEW ECS cluster [ai-devops-cluster]: ") or "ai-devops-cluster"
                 self.resource_configuration['create_new'] = True
                 return True
             elif 1 <= choice_idx <= len(existing_clusters):
                 selected_cluster = existing_clusters[choice_idx - 1]
                 logger.info(f"Selected existing ECS cluster: {selected_cluster.get('name')}")
                 self.selected_resource_details = {**selected_cluster, 'type': 'AWS ECS Cluster (Existing)'}
                 self.resource_configuration['cluster_name'] = selected_cluster.get('name')
                 self.resource_configuration['cluster_arn'] = selected_cluster.get('arn')
                 self.resource_configuration['create_new'] = False
                 return True
             else: logger.error("Invalid selection."); return False
         except ValueError: logger.error("Invalid input."); return False

    def _configure_or_select_aws_lambda(self, lambda_client, iam_client) -> bool:
         # ... (Implementation looks okay, ensure keys are handled) ...
         existing_functions = []
         try:
             paginator = lambda_client.get_paginator('list_functions')
             for page in paginator.paginate():
                  for func in page.get('Functions', []):
                      if func.get('FunctionName'): # Ensure name exists
                           existing_functions.append({
                                'name': func['FunctionName'], 'arn': func.get('FunctionArn'), 'runtime': func.get('Runtime'),
                                'memory': func.get('MemorySize'), 'role_arn': func.get('Role')
                           })
         except ClientError as e: logger.warning(f"Could not list existing Lambda functions: {e}")

         print("\nLambda Function Options:\n0. Create NEW Lambda Function")
         if existing_functions:
             print("--- Existing Functions ---") # Simplified display
             for i, func in enumerate(existing_functions, 1): print(f"{i}. {func.get('name')} (Runtime: {func.get('runtime')})")
             print("-------------------------")
         choice = input(f"Select option (0-{len(existing_functions)}): ")
         try:
             choice_idx = int(choice)
             if choice_idx == 0:
                 logger.info("Configuring NEW Lambda function...")
                 self.resource_configuration['function_name'] = input("Enter Lambda function name [ai-devops-function]: ") or "ai-devops-function"
                 memory_values = [128, 256, 512, 1024]; print("\nSelect Lambda memory (MB):")
                 for i, mem in enumerate(memory_values, 1): print(f"{i}. {mem}")
                 mem_choice = input(f"Memory (1-{len(memory_values)}) [default: {memory_values[0]}]: ")
                 idx = int(mem_choice) - 1 if mem_choice.isdigit() else -1
                 self.resource_configuration['memory'] = memory_values[idx] if 0 <= idx < len(memory_values) else memory_values[0]
                 self.resource_configuration['create_new'] = True
                 return True
             elif 1 <= choice_idx <= len(existing_functions):
                 selected_function = existing_functions[choice_idx - 1]
                 logger.info(f"Selected existing Lambda function: {selected_function.get('name')}")
                 self.selected_resource_details = {**selected_function, 'type': 'AWS Lambda Function (Existing)'}
                 self.resource_configuration['function_name'] = selected_function.get('name')
                 self.resource_configuration['memory'] = selected_function.get('memory')
                 self.resource_configuration['create_new'] = False
                 return True
             else: logger.error("Invalid selection."); return False
         except ValueError: logger.error("Invalid input."); return False

    # --- Azure Configuration ---
    def _configure_azure_resource(self) -> bool:
        credential = self._get_azure_credential()
        subscription_id = self.cloud_credentials.get('subscription_id')
        if not credential or not subscription_id: return False
        logger.info(f"Configuring Azure resource target for subscription: {subscription_id}...")
        resource_client = azure.mgmt.resource.ResourceManagementClient(credential, subscription_id)
        compute_client = azure.mgmt.compute.ComputeManagementClient(credential, subscription_id)

        # Resource Group Selection/Creation (Needs implementation or reuse from previous versions)
        logger.info("Checking Azure Resource Groups...")
        # Simplified RG Selection: Assume it exists or create new
        rg_name = input("Enter Resource Group name (will be created if not found): ")
        location = input("Enter Location (e.g., eastus - required if creating): ")
        if not rg_name or not location: logger.error("RG Name and Location required."); return False
        try:
             resource_client.resource_groups.create_or_update(rg_name, {'location': location})
             logger.info(f"Resource group '{rg_name}' ensured in {location}.")
             self.resource_configuration['resource_group'] = rg_name
             self.resource_configuration['location'] = location
        except Exception as e:
             logger.error(f"Failed to ensure resource group '{rg_name}': {e}"); return False

        print("\nAvailable Azure deployment targets:\n1. Azure VM\n2. App Service")
        choice = input("Select target type (1-2): ")
        if choice == '1':
            self.resource_configuration['type'] = 'vm';
            return self._configure_or_select_azure_vm(compute_client, rg_name, location)
        elif choice == '2':
             self.resource_configuration['type'] = 'app_service'
             self.resource_configuration['app_name'] = input("App Service name [ai-devops-webapp]: ") or "ai-devops-webapp"
             logger.info(f"App Service '{self.resource_configuration['app_name']}' configured.")
             self.selected_resource_details = {'type': 'Azure App Service (Target Name)', 'name': self.resource_configuration['app_name'], 'resource_group': rg_name}
             self.resource_configuration['create_new'] = False # Assume App Service not created here
             return True
        else: logger.error("Invalid type"); return False

    def _configure_or_select_azure_vm(self, compute_client, rg_name, location) -> bool:
        # ... (Implementation is mostly correct, ensure keys are handled) ...
        existing_vms = []
        try:
             logger.info(f"Listing VMs in resource group '{rg_name}'...")
             vms_list = compute_client.virtual_machines.list(rg_name)
             for vm in vms_list:
                  if vm.id and vm.name: # Basic check
                       power_state, public_ip = "Unknown", "N/A" # Simplified details for listing
                       try: # Get power state safely
                           vm_view = compute_client.virtual_machines.instance_view(rg_name, vm.name)
                           power_status = next((s for s in vm_view.statuses if s.code.startswith('PowerState/')), None)
                           if power_status: power_state = power_status.code.split('/')[-1]
                       except Exception: pass # Ignore errors getting view details for listing
                       existing_vms.append({
                           'id': vm.id, 'name': vm.name, 'size': vm.hardware_profile.vm_size if vm.hardware_profile else '?',
                           'state': power_state, 'location': vm.location,
                           'admin_username': vm.os_profile.admin_username if vm.os_profile else '?', 'ip': public_ip
                       })
        except Exception as e: logger.warning(f"Could not list existing Azure VMs in {rg_name}: {e}")

        print(f"\nAzure VM Options:\n0. Create NEW VM in {rg_name} ({location})")
        if existing_vms:
            print("--- Existing VMs ---")
            for i, vm in enumerate(existing_vms, 1): print(f"{i}. {vm.get('name')} - Size: {vm.get('size')}, State: {vm.get('state')}")
            print("--------------------")
        choice = input(f"Select option (0-{len(existing_vms)}): ")
        try:
            choice_idx = int(choice)
            if choice_idx == 0:
                 logger.info("Configuring NEW Azure VM...")
                 vm_sizes = ['Standard_B1s', 'Standard_B2s', 'Standard_D2s_v3']
                 print("\nSelect NEW VM size:")
                 for i, size in enumerate(vm_sizes, 1): print(f"{i}. {size}")
                 vm_choice = input(f"VM size (1-{len(vm_sizes)}) [default: {vm_sizes[0]}]: ")
                 idx = int(vm_choice) - 1 if vm_choice.isdigit() else -1
                 self.resource_configuration['vm_size'] = vm_sizes[idx] if 0 <= idx < len(vm_sizes) else vm_sizes[0]
                 self.resource_configuration['vm_name'] = input("Enter NEW VM name [ai-devops-vm]: ") or "ai-devops-vm"
                 self.resource_configuration['admin_username'] = input("Admin username for NEW VM [azureuser]: ") or "azureuser"
                 self.resource_configuration['create_new'] = True
                 return True
            elif 1 <= choice_idx <= len(existing_vms):
                 selected_vm = existing_vms[choice_idx - 1]
                 logger.info(f"Selected existing Azure VM: {selected_vm.get('name')}")
                 self.selected_resource_details = {**selected_vm, 'type': 'Azure VM (Existing)'}
                 logger.warning(f"Selected existing VM '{selected_vm.get('name')}' with admin user '{selected_vm.get('admin_username')}'. Ensure you have the private key.")
                 self.resource_configuration['vm_name'] = selected_vm.get('name')
                 self.resource_configuration['vm_size'] = selected_vm.get('size')
                 self.resource_configuration['admin_username'] = selected_vm.get('admin_username')
                 self.resource_configuration['create_new'] = False
                 self.ssh_key_paths = {}
                 return True
            else: logger.error("Invalid selection."); return False
        except ValueError: logger.error("Invalid input."); return False

    # --- GCP Configuration ---
    def _configure_gcp_resource(self) -> bool:
        credentials, project_id = self._get_gcp_credential()
        if not credentials or not project_id: return False
        logger.info(f"Configuring GCP resource target for project: {project_id}...")
        # Store project_id in config for later use
        self.resource_configuration['project_id'] = project_id
        compute_client = compute_v1.InstancesClient(credentials=credentials)

        print("\nAvailable GCP deployment targets:\n1. Compute Engine (VM)\n2. Cloud Run")
        choice = input("Select target type (1-2): ")
        if choice == '1':
            self.resource_configuration['type'] = 'vm'
            zone = input("Enter zone for VM search/creation (e.g., us-central1-a): ") or "us-central1-a"
            self.resource_configuration['zone'] = zone
            return self._configure_or_select_gcp_vm(compute_client, project_id, zone)
        elif choice == '2':
            self.resource_configuration['type'] = 'cloud_run'
            self.resource_configuration['service_name'] = input("Cloud Run service name [ai-devops-service]: ") or "ai-devops-service"
            self.resource_configuration['region'] = input("Cloud Run region [us-central1]: ") or "us-central1"
            logger.info(f"Cloud Run service '{self.resource_configuration['service_name']}' configured.")
            self.selected_resource_details = {'type': 'GCP Cloud Run (Target Name)', 'name': self.resource_configuration['service_name'], 'region': self.resource_configuration['region'], 'project_id': project_id}
            self.resource_configuration['create_new'] = False
            return True
        else: logger.error("Invalid type"); return False

    def _configure_or_select_gcp_vm(self, compute_client, project_id, zone) -> bool:
        # ... (Implementation is mostly correct, ensure keys are handled) ...
        existing_vms = []
        try:
             logger.info(f"Listing VMs in project '{project_id}', zone '{zone}'...")
             request = compute_v1.ListInstancesRequest(project=project_id, zone=zone)
             vm_list = compute_client.list(request=request)
             for vm in vm_list:
                  if vm.id and vm.name: # Basic check
                       public_ip = "N/A"
                       if vm.network_interfaces and vm.network_interfaces[0].access_configs:
                           public_ip = vm.network_interfaces[0].access_configs[0].nat_ip
                       existing_vms.append({
                           'id': vm.id, 'name': vm.name, 'type': vm.machine_type.split('/')[-1],
                           'status': vm.status, 'zone': zone, 'ip': public_ip, 'ssh_user': 'gcpuser' # Assumption
                       })
        except Exception as e: logger.warning(f"Could not list existing GCP VMs in {zone}: {e}")

        print(f"\nGCP Compute Engine VM Options:\n0. Create NEW VM in {zone}")
        if existing_vms:
            print("--- Existing VMs ---")
            for i, vm in enumerate(existing_vms, 1): print(f"{i}. {vm.get('name')} - Type: {vm.get('type')}, Status: {vm.get('status')}, IP: {vm.get('ip')}")
            print("--------------------")
        choice = input(f"Select option (0-{len(existing_vms)}): ")
        try:
            choice_idx = int(choice)
            if choice_idx == 0:
                 logger.info("Configuring NEW GCP VM...")
                 machine_types = ['e2-micro', 'e2-small', 'n1-standard-1']
                 print("\nSelect NEW machine type:")
                 for i, mtype in enumerate(machine_types, 1): print(f"{i}. {mtype}")
                 mchoice = input(f"Machine type (1-{len(machine_types)}) [default: {machine_types[0]}]: ")
                 idx = int(mchoice) - 1 if mchoice.isdigit() else -1
                 self.resource_configuration['machine_type'] = machine_types[idx] if 0 <= idx < len(machine_types) else machine_types[0]
                 self.resource_configuration['instance_name'] = input("NEW instance name [ai-devops-instance]: ") or "ai-devops-instance"
                 self.resource_configuration['create_new'] = True
                 return True
            elif 1 <= choice_idx <= len(existing_vms):
                 selected_vm = existing_vms[choice_idx - 1]
                 logger.info(f"Selected existing GCP VM: {selected_vm.get('name')}")
                 self.selected_resource_details = {**selected_vm, 'type': 'GCP Compute Engine VM (Existing)'}
                 logger.warning(f"Selected existing VM '{selected_vm.get('name')}'. Ensure you have the SSH key authorized.")
                 self.resource_configuration['instance_name'] = selected_vm.get('name')
                 self.resource_configuration['machine_type'] = selected_vm.get('type')
                 self.resource_configuration['zone'] = selected_vm.get('zone')
                 self.resource_configuration['create_new'] = False
                 self.ssh_key_paths = {}
                 return True
            else: logger.error("Invalid selection."); return False
        except ValueError: logger.error("Invalid input."); return False


    # --- Resource Creation Methods (Assumed Correct from Previous Fixes) ---
    # These only run if create_new is True
    def _create_aws_ec2_instance(self, ec2_client) -> bool:
        logger.info("Executing creation of NEW EC2 instance...")
        instance_type = self.resource_configuration.get('instance_type', 't2.micro')
        key_name_base = "ai-devops-ec2-key"
        sg_name = "ai-devops-ec2-sg"
        region = self.resource_configuration.get('region', 'us-east-1') # Get region stored earlier
        try:
             private_key_path, public_key_material, _ = generate_ssh_key_pair(key_name_base)
             if not private_key_path or not public_key_material: return False
             self.ssh_key_paths['private'] = private_key_path; self.ssh_key_paths['public'] = f"{private_key_path}.pub"
             key_pair_name_aws = None
             try:
                  ec2_client.describe_key_pairs(KeyNames=[key_name_base])
                  key_pair_name_aws = key_name_base; logger.info(f"Using existing AWS key pair: {key_name_base}")
                  self.ssh_key_paths['key_name'] = key_pair_name_aws
             except ClientError as e:
                  if e.response['Error']['Code'] == 'InvalidKeyPair.NotFound':
                       logger.info(f"Importing local public key to AWS as {key_name_base}...")
                       key_pair = ec2_client.import_key_pair(KeyName=key_name_base, PublicKeyMaterial=public_key_material.encode('utf-8'))
                       key_pair_name_aws = key_pair['KeyName']; self.ssh_key_paths['key_name'] = key_pair_name_aws
                       logger.info(f"Imported key pair: {key_pair_name_aws}")
                  else: raise
             if not key_pair_name_aws: logger.error("Failed to get AWS key pair name."); return False
             # SG Logic...
             sg_id = None
             try:
                 response = ec2_client.describe_security_groups(GroupNames=[sg_name])
                 sg_id = response['SecurityGroups'][0]['GroupId']; logger.info(f"Using existing SG: {sg_name} ({sg_id})")
             except ClientError as e:
                 if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
                      logger.info(f"Creating new SG: {sg_name}")
                      vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
                      vpc_id = vpcs['Vpcs'][0]['VpcId'] if vpcs.get('Vpcs') else None
                      if not vpc_id:
                         # If no default VPC, try to find any VPC
                         all_vpcs = ec2_client.describe_vpcs()
                         if all_vpcs.get('Vpcs'):
                             vpc_id = all_vpcs['Vpcs'][0]['VpcId']
                             logger.warning(f"No default VPC found, using first available VPC: {vpc_id}")
                         else:
                             logger.error("No VPCs found in the account/region.")
                             return False
                      sg = ec2_client.create_security_group(GroupName=sg_name, Description='AI DevOps SG', VpcId=vpc_id)
                      sg_id = sg['GroupId']
                      ec2_client.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[
                            {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}, # SSH
                            {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}, # HTTP
                            {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]} # HTTPS (often needed)
                      ])
                      logger.info(f"Created SG {sg_id} and allowed SSH/HTTP/HTTPS.")
                 else: raise
             if not sg_id: logger.error("Failed to get SG ID."); return False

             # --- AMI Logic (Updated for Ubuntu 22.04 LTS) ---
             logger.info("Finding latest Ubuntu Server 22.04 LTS (Jammy) HVM SSD AMI...")
             filters = [
                 {'Name': 'name', 'Values': ['ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*']},
                 {'Name': 'architecture', 'Values': ['x86_64']},
                 {'Name': 'state', 'Values': ['available']},
                 {'Name': 'virtualization-type', 'Values': ['hvm']}
             ]
             # Canonical's owner ID for official Ubuntu AMIs
             owner_id = '099720109477'
             images = ec2_client.describe_images(Owners=[owner_id], Filters=filters)

             if not images or not images.get('Images'):
                 logger.error("Could not find a suitable Ubuntu 22.04 LTS AMI. Check filters/region.")
                 # Fallback or specific error handling could go here
                 # Maybe try Amazon Linux 2 as a fallback?
                 logger.warning("Falling back to Amazon Linux 2 AMI search...")
                 images = ec2_client.describe_images(Owners=['amazon'], Filters=[{'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},{'Name':'state', 'Values':['available']}])
                 if not images or not images.get('Images'):
                     logger.error("Could not find Amazon Linux 2 AMI either.")
                     return False
                 ami_id = sorted(images['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId']
                 default_ssh_user = 'ec2-user' # Default for Amazon Linux
                 logger.info(f"Using fallback Amazon Linux 2 AMI: {ami_id}")
             else:
                 # Sort by creation date to get the latest one
                 ami_id = sorted(images['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId']
                 default_ssh_user = 'ubuntu' # Default user for Ubuntu AMIs
                 logger.info(f"Using Ubuntu 22.04 LTS AMI: {ami_id}")
             # --- End of Updated AMI Logic ---

             # Launch Instance...
             # Use a generic name unless user specifies one later
             instance_name_tag = self.resource_configuration.get('instance_name', 'ai-devops-instance')
             run_response = ec2_client.run_instances(
                 ImageId=ami_id, InstanceType=instance_type, KeyName=key_pair_name_aws, SecurityGroupIds=[sg_id], MinCount=1, MaxCount=1,
                 TagSpecifications=[{'ResourceType': 'instance','Tags': [{'Key': 'Name', 'Value': instance_name_tag},{'Key':'CreatedBy','Value':'ai-devops-tool'}]}]
             )
             instance_id = run_response['Instances'][0]['InstanceId']; logger.info(f"Instance requested: {instance_id}. Waiting...")
             waiter = ec2_client.get_waiter('instance_running'); waiter.wait(InstanceIds=[instance_id]); logger.info("Instance running.")
             desc_response = ec2_client.describe_instances(InstanceIds=[instance_id])
             instance_info = desc_response['Reservations'][0]['Instances'][0]
             self.created_resource_details = {
                 'type': 'AWS EC2 Instance', 'id': instance_id, 'region': region, 'instance_type': instance_type, 'ami_id': ami_id,
                 'key_pair_name': key_pair_name_aws, 'security_group_id': sg_id, 'security_group_name': sg_name,
                 'public_ip': instance_info.get('PublicIpAddress'), 'public_dns': instance_info.get('PublicDnsName'),
                 'ssh_user': default_ssh_user, # <-- Use the correct user based on AMI found
                 'ssh_key_private_path': self.ssh_key_paths.get('private')
             }
             logger.info(f"EC2 Instance Created: ID={instance_id}, IP={self.created_resource_details['public_ip']}, User={default_ssh_user}")
             return True
        except ClientError as e: logger.error(f"AWS API error creating EC2: {e}"); return False
        except Exception as e: logger.error(f"Unexpected error creating EC2: {e}", exc_info=True); return False

    def _create_aws_ecs_cluster(self, ecs_client) -> bool:
        logger.info("Executing creation of NEW ECS cluster...")
        # ... (Full implementation from previous working version) ...
        cluster_name = self.resource_configuration.get('cluster_name', 'ai-devops-cluster')
        region = self.resource_configuration.get('region', 'us-east-1')
        try:
             response = ecs_client.create_cluster(clusterName=cluster_name)
             cluster_arn = response['cluster']['clusterArn']
             self.created_resource_details = {'type': 'AWS ECS Cluster', 'name': cluster_name, 'arn': cluster_arn, 'region': region}
             logger.info(f"ECS Cluster created: {cluster_arn}")
             return True
        except ClientError as e:
             if e.response['Error']['Code'] == 'InvalidParameterException' and 'already exists' in str(e):
                  logger.warning(f"ECS Cluster '{cluster_name}' already exists. Using existing.")
                  # Try to get ARN if possible
                  try:
                       desc = ecs_client.describe_clusters(clusters=[cluster_name])
                       if desc.get('clusters'):
                           self.created_resource_details = {'type': 'AWS ECS Cluster (Existing - Found)', 'name': cluster_name, 'arn': desc['clusters'][0]['clusterArn'], 'region': region}
                           return True # Still counts as success for workflow
                  except Exception: pass # Ignore if describe fails
                  # Fallback if describe failed
                  self.created_resource_details = {'type': 'AWS ECS Cluster (Existing - Name Only)', 'name': cluster_name, 'arn': 'N/A', 'region': region}
                  return True # Assume success for workflow
             logger.error(f"AWS API error creating ECS cluster: {e}"); return False
        except Exception as e: logger.error(f"Unexpected error creating ECS cluster: {e}"); return False

    def _create_aws_lambda_function(self, lambda_client, iam_client) -> bool:
        logger.info("Executing creation of NEW Lambda function...")
        # ... (Full implementation from previous working version) ...
        function_name = self.resource_configuration.get('function_name', 'ai-devops-function')
        memory = self.resource_configuration.get('memory', 128)
        region = self.resource_configuration.get('region', 'us-east-1')
        runtime = 'python3.9' # Default, adjust based on detected_stack
        if self.detected_stack == 'nodejs': runtime = 'nodejs18.x'
        elif self.detected_stack == 'java': runtime = 'java11'
        elif self.detected_stack == 'golang': runtime = 'go1.x'
        # Add others

        role_name = f"{function_name}-execution-role"
        try:
             # IAM Role
             role_arn = None
             try:
                  role_arn = iam_client.get_role(RoleName=role_name)['Role']['Arn']; logger.info(f"Using existing role: {role_name}")
             except ClientError as e:
                  if e.response['Error']['Code'] == 'NoSuchEntity':
                       logger.info(f"Creating new role: {role_name}")
                       assume_role_policy = json.dumps({"Version": "2012-10-17","Statement": [{"Effect": "Allow","Principal": {"Service": "lambda.amazonaws.com"},"Action": "sts:AssumeRole"}]})
                       role_response = iam_client.create_role(RoleName=role_name, AssumeRolePolicyDocument=assume_role_policy)
                       role_arn = role_response['Role']['Arn']
                       policy_arn = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
                       iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                       logger.info("Attached basic execution policy. Waiting for propagation...")
                       time.sleep(10) # IAM is eventually consistent
                  else: raise
             if not role_arn: logger.error("Failed to get/create IAM role."); return False

             # Dummy Code
             handler_name, dummy_filename, dummy_content = "lambda_function.lambda_handler", "lambda_function.py", "def lambda_handler(e,c): return {'statusCode':200,'body':'OK'}"
             if runtime.startswith('nodejs'): handler_name, dummy_filename, dummy_content = "index.handler", "index.js", "exports.handler=async(e)=>{return{statusCode:200,body:'OK'}}"
             # Add others

             zip_path = os.path.join(tempfile.gettempdir(), f"{function_name}_dummy.zip")
             dummy_path = os.path.join(tempfile.gettempdir(), dummy_filename)
             with open(dummy_path, 'w') as f: f.write(dummy_content)
             import zipfile
             with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf: zf.write(dummy_path, arcname=dummy_filename)
             with open(zip_path, 'rb') as f: zip_content = f.read()

             # Create Function
             logger.info(f"Creating function {function_name}...")
             create_response = lambda_client.create_function(
                 FunctionName=function_name, Runtime=runtime, Role=role_arn, Handler=handler_name,
                 Code={'ZipFile': zip_content}, MemorySize=memory, Publish=True
             )
             function_arn = create_response['FunctionArn']
             self.created_resource_details = {
                 'type': 'AWS Lambda Function', 'name': function_name, 'arn': function_arn,
                 'runtime': runtime, 'memory': memory, 'role_arn': role_arn, 'region': region
             }
             logger.info(f"Lambda function created: {function_arn}")
             # Cleanup dummy files
             try: os.remove(dummy_path); os.remove(zip_path)
             except OSError: logger.warning("Could not cleanup dummy Lambda files.")
             return True
        except ClientError as e:
             if e.response['Error']['Code'] == 'ResourceConflictException':
                  logger.warning(f"Lambda function '{function_name}' already exists. Skipping creation.")
                  # Try get existing ARN
                  try: arn = lambda_client.get_function(FunctionName=function_name)['Configuration']['FunctionArn']
                  except Exception: arn = 'N/A (Already Exists)'
                  self.created_resource_details = {'type': 'AWS Lambda Function (Existing - Found)', 'name': function_name, 'arn': arn, 'region': region}
                  return True # Treat as success for workflow
             logger.error(f"AWS API error creating Lambda: {e}"); return False
        except Exception as e: logger.error(f"Unexpected error creating Lambda: {e}", exc_info=True); return False

    def _create_azure_vm(self, compute_client, network_client, resource_client) -> bool:
        logger.info("Executing creation of NEW Azure VM...")
        # ... (Full implementation from previous working version) ...
        rg_name = self.resource_configuration.get('resource_group')
        location = self.resource_configuration.get('location')
        vm_name = self.resource_configuration.get('vm_name')
        vm_size = self.resource_configuration.get('vm_size')
        admin_username = self.resource_configuration.get('admin_username')
        if not all([rg_name, location, vm_name, vm_size, admin_username]):
             logger.error("Missing Azure VM configuration parameters."); return False
        key_name_base = f"ai-devops-{vm_name}-key"
        try:
             # SSH Key
             private_key_path, public_key_content, _ = generate_ssh_key_pair(key_name_base)
             if not private_key_path: return False
             self.ssh_key_paths['private'] = private_key_path; self.ssh_key_paths['public'] = f"{private_key_path}.pub"
             # Network resources (VNet, Subnet, PIP, NIC)
             vnet_name = f"{vm_name}-vnet"; subnet_name = "default"; public_ip_name = f"{vm_name}-pip"; nic_name = f"{vm_name}-nic"
             logger.info("Ensuring network resources...")
             vnet_poller = network_client.virtual_networks.begin_create_or_update(rg_name,vnet_name,{"location":location,"address_space":{"address_prefixes":["10.0.0.0/16"]}})
             vnet_result = vnet_poller.result()
             subnet_poller = network_client.subnets.begin_create_or_update(rg_name,vnet_name,subnet_name,{"address_prefix":"10.0.0.0/24"})
             subnet_result = subnet_poller.result()
             pip_poller = network_client.public_ip_addresses.begin_create_or_update(rg_name,public_ip_name,{"location":location,"sku":{"name":"Standard"},"public_ip_allocation_method":"Static"})
             pip_result = pip_poller.result()
             nic_poller = network_client.network_interfaces.begin_create_or_update(rg_name,nic_name,{"location":location,"ip_configurations":[{"name":"ipconfig1","subnet":{"id":subnet_result.id},"public_ip_address":{"id":pip_result.id}}]})
             nic_result = nic_poller.result()
             logger.info("Network resources ready.")
             # VM Config
             vm_parameters = {
                  "location": location, "name": vm_name,
                  "properties": {
                       "hardwareProfile": {"vmSize": vm_size},
                       "storageProfile": {"imageReference": {"publisher":"Canonical","offer":"UbuntuServer","sku":"20.04-LTS","version":"latest"}, "osDisk": {"createOption":"FromImage","managedDisk":{"storageAccountType":"Standard_LRS"}}},
                       "osProfile": {"computerName":vm_name,"adminUsername":admin_username,"linuxConfiguration":{"disablePasswordAuthentication":True,"ssh":{"publicKeys":[{"path":f"/home/{admin_username}/.ssh/authorized_keys","keyData":public_key_content}]}}},
                       "networkProfile": {"networkInterfaces": [{"id":nic_result.id,"properties":{"primary":True}}]}
                  }
             }
             # Create VM
             logger.info(f"Creating VM '{vm_name}'...")
             vm_poller = compute_client.virtual_machines.begin_create_or_update(rg_name, vm_name, vm_parameters)
             vm_result = vm_poller.result(); logger.info("VM creation polling finished.")
             # Get updated IP
             pip_details = network_client.public_ip_addresses.get(rg_name, public_ip_name)
             public_ip_address = pip_details.ip_address if pip_details else "N/A"
             self.created_resource_details = {
                  'type': 'Azure VM', 'name': vm_result.name, 'id': vm_result.id, 'resource_group': rg_name, 'location': location,
                  'size': vm_size, 'public_ip': public_ip_address, 'admin_username': admin_username,
                  'ssh_key_private_path': self.ssh_key_paths.get('private')
             }
             logger.info(f"Azure VM Created: Name={vm_result.name}, IP={public_ip_address}")
             # NSG Rule (best effort)
             try:
                  nsg_name = nic_result.network_security_group.id.split('/')[-1] if nic_result.network_security_group else f"{vm_name}-nsg"
                  logger.info(f"Ensuring NSG '{nsg_name}' and SSH rule...")
                  try: network_client.network_security_groups.get(rg_name, nsg_name)
                  except AzureResourceNotFoundError:
                       logger.info(f"NSG not found, creating '{nsg_name}'...")
                       nsg_poller = network_client.network_security_groups.begin_create_or_update(rg_name, nsg_name, {"location": location})
                       nsg_result = nsg_poller.result()
                       nic_result.network_security_group = nsg_result # Associate NSG with NIC
                       nic_update_poller = network_client.network_interfaces.begin_create_or_update(rg_name, nic_name, nic_result)
                       nic_update_poller.result(); logger.info("Associated NSG with NIC.")
                  rule_poller = network_client.security_rules.begin_create_or_update(rg_name,nsg_name,"AllowSSH",{"protocol":"Tcp","source_address_prefix":"*","destination_address_prefix":"*","access":"Allow","direction":"Inbound","source_port_range":"*","destination_port_range":"22","priority":100})
                  rule_poller.result(); logger.info("SSH rule ensured.")
             except Exception as nsg_e: logger.warning(f"Could not ensure NSG rule: {nsg_e}")
             return True
        except azure.core.exceptions.HttpResponseError as e: logger.error(f"Azure API error creating VM: {e.message}"); return False
        except Exception as e: logger.error(f"Unexpected error creating Azure VM: {e}", exc_info=True); return False

    def _create_gcp_vm(self, compute_client: compute_v1.InstancesClient, credentials, project_id: str) -> bool:
        logger.info("Executing creation of NEW GCP VM...")
        # ... (Full implementation from previous working version) ...
        instance_name = self.resource_configuration.get('instance_name')
        zone = self.resource_configuration.get('zone')
        machine_type = self.resource_configuration.get('machine_type')
        if not all([instance_name, zone, machine_type]): logger.error("Missing GCP VM config."); return False
        key_name_base = f"ai-devops-{instance_name}-key"; ssh_user = "gcpuser"
        try:
            # SSH Key
            private_key_path, public_key_content, _ = generate_ssh_key_pair(key_name_base)
            if not private_key_path: return False
            self.ssh_key_paths['private'] = private_key_path; self.ssh_key_paths['public'] = f"{private_key_path}.pub"
            ssh_key_metadata = f"{ssh_user}:{public_key_content}"
            # Image
            image_client = compute_v1.ImagesClient(credentials=credentials)
            latest_image = image_client.get_from_family(project="debian-cloud", family="debian-11")
            source_disk_image = latest_image.self_link; logger.info(f"Using image: {source_disk_image}")
            # Machine Type URL
            machine_type_url = f"zones/{zone}/machineTypes/{machine_type}"
            # Instance Config
            instance_config = compute_v1.Instance(
                name=instance_name, machine_type=machine_type_url,
                network_interfaces=[compute_v1.NetworkInterface(name="global/networks/default", access_configs=[compute_v1.AccessConfig(name="External NAT", type_="ONE_TO_ONE_NAT")])],
                disks=[compute_v1.AttachedDisk(initialize_params=compute_v1.AttachedDiskInitializeParams(source_image=source_disk_image, disk_size_gb=10), auto_delete=True, boot=True)],
                metadata=compute_v1.Metadata(items=[compute_v1.Items(key="ssh-keys", value=ssh_key_metadata)]),
                tags=compute_v1.Tags(items=["ai-devops-instance", "http-server", "https-server"])
            )
            # Insert Instance
            logger.info(f"Creating instance '{instance_name}'...")
            operation = compute_client.insert(project=project_id, zone=zone, instance_resource=instance_config)
            # Wait (using google.api_core blocking wait)
            logger.info("Waiting for instance creation...")
            operation_client = compute_v1.ZoneOperationsClient(credentials=credentials) # Client to wait on operations
            # This raises TimeoutError on timeout, or returns finished operation
            operation_client.wait(project=project_id, zone=zone, operation=operation.name, timeout=300) # 5 min timeout
            # Re-fetch operation status if needed, wait() should ensure it's done or failed
            final_operation = operation_client.get(project=project_id, zone=zone, operation=operation.name)
            if final_operation.error: raise google_exceptions.GoogleAPICallError(f"Instance creation failed: {final_operation.error}")
            logger.info("Instance creation finished.")
            # Get Details
            instance_details = compute_client.get(project=project_id, zone=zone, instance=instance_name)
            public_ip = instance_details.network_interfaces[0].access_configs[0].nat_ip if instance_details.network_interfaces and instance_details.network_interfaces[0].access_configs else "N/A"
            self.created_resource_details = {
            'type': 'GCP Compute Engine VM', 'name': instance_name, 'id': instance_details.id, 'project_id': project_id, 'zone': zone,
            'machine_type': machine_type, 'public_ip': public_ip, 'ssh_user': ssh_user,
            'ssh_key_private_path': self.ssh_key_paths.get('private')
            }
            logger.info(f"GCP VM Created: Name={instance_name}, IP={public_ip}")
            # Firewall Rule
            firewall_client = compute_v1.FirewallsClient(credentials=credentials); ssh_rule_name = "ai-devops-allow-ssh"
            ssh_rule = compute_v1.Firewall(
            name=ssh_rule_name, network="global/networks/default", direction=compute_v1.Firewall.Direction.INGRESS, priority=1000,
            allowed=[compute_v1.Allowed(ip_protocol="tcp", ports=["22"])], source_ranges=["0.0.0.0/0"], target_tags=["ai-devops-instance"]
            )
            try:
                logger.info(f"Ensuring firewall rule '{ssh_rule_name}'...")
                fw_op = firewall_client.insert(project=project_id, firewall_resource=ssh_rule)
                # Wait for firewall op if needed (usually fast)
                # fw_op.result(timeout=60)
                logger.info(f"Firewall rule '{ssh_rule_name}' ensured.")
            except google_exceptions.Conflict: logger.info(f"Firewall rule '{ssh_rule_name}' already exists.")
            except Exception as fw_e: logger.warning(f"Could not ensure SSH firewall rule: {fw_e}")
            return True
        except google_exceptions.GoogleAPICallError as e: logger.error(f"GCP API error creating VM: {e}"); return False
        except Exception as e: logger.error(f"Unexpected error creating GCP VM: {e}", exc_info=True); return False


    # --- CI/CD Generation (LLM - Assumed Correct from Previous Fixes) ---
    def generate_cicd_config(self) -> bool:
        logger.info("Attempting to generate CI/CD pipeline configuration via LLM...")
        if not self.openai_client:
            logger.error("OpenAI client not initialized. Cannot use LLM."); return False

        # Determine platform and output file path (relative to repo root)
        repo_info = self.repo_url.lower(); target_ci_path = None
        if 'github.com' in repo_info:
            self.ci_platform = "GitHub Actions"; target_ci_path = '.github/workflows/ai-devops-cicd.yml'
        elif 'gitlab.com' in repo_info:
            self.ci_platform = "GitLab CI"; target_ci_path = '.gitlab-ci.yml'
        elif 'bitbucket.org' in repo_info:
            self.ci_platform = "Bitbucket Pipelines"; target_ci_path = 'bitbucket-pipelines.yml'
        else:
            if self.is_github_repo:
                logger.warning("Unknown Git host, but assuming GitHub due to API client presence.");
                self.ci_platform = "GitHub Actions"; target_ci_path = '.github/workflows/ai-devops-cicd.yml'
            else:
                self.ci_platform = "GitHub Actions" # Default for local fallback
                workflow_dir = os.path.join(self.repo_path, '.github', 'workflows'); os.makedirs(workflow_dir, exist_ok=True);
                target_ci_path = os.path.join(workflow_dir, 'ai-devops-cicd.yml') # Local path
                logger.warning(f"Unknown Git host and not using GitHub API. Defaulting to GitHub Actions format locally at: {target_ci_path}")

        if not target_ci_path:
            logger.error("Could not determine CI/CD output file path."); return False
        logger.info(f"Targeting CI/CD Platform: {self.ci_platform}, Path: {target_ci_path}")


        resource_details_for_llm = self.selected_resource_details or self.created_resource_details
        target_type = self.resource_configuration.get('type', 'unknown')
        is_vm_like = target_type in ['ec2', 'vm']
        
        deploy_ip = resource_details_for_llm.get('public_ip', 'YOUR_SERVER_IP')
        deploy_user = resource_details_for_llm.get('ssh_user') or resource_details_for_llm.get('admin_username', 'YOUR_SSH_USER')
        artifact_name = "app.zip" # Consistent artifact name
        ssh_secret_name = "DEPLOY_SSH_PRIVATE_KEY"
        
        if not is_vm_like:
            deploy_ip = "N/A (Non-VM Target)"
            deploy_user = "N/A (Non-VM Target)"

        logger.info(f"Context for LLM: Stack={self.detected_stack}, Provider={self.cloud_provider}, Target={target_type}, IP={deploy_ip}, User={deploy_user}")

        # Ensure necessary keys exist in resource_details for LLM context, even if None
        if self.resource_configuration.get('type') in ['ec2', 'vm']:
             resource_details_for_llm.setdefault('public_ip', None)
             resource_details_for_llm.setdefault('ssh_user', None) # Or admin_username for Azure
             resource_details_for_llm.setdefault('admin_username', None)
             resource_details_for_llm.setdefault('id', None)
             resource_details_for_llm.setdefault('name', None)
        elif self.resource_configuration.get('type') == 'ecs':
             resource_details_for_llm.setdefault('cluster_name', None)
             resource_details_for_llm.setdefault('service_name', 'ai-devops-service') # Assume convention
             resource_details_for_llm.setdefault('cluster_arn', None)
        elif self.resource_configuration.get('type') == 'lambda':
             resource_details_for_llm.setdefault('function_name', None)
             resource_details_for_llm.setdefault('arn', None)
        elif self.resource_configuration.get('type') == 'app_service':
             resource_details_for_llm.setdefault('app_name', None)
             resource_details_for_llm.setdefault('resource_group', None)
        elif self.resource_configuration.get('type') == 'cloud_run':
             resource_details_for_llm.setdefault('service_name', None)
             resource_details_for_llm.setdefault('region', None)
             resource_details_for_llm.setdefault('project_id', None)
        # Add other types if needed

        # --- Construct the Enhanced Prompt ---
        prompt = f"""
        Generate a CI/CD pipeline configuration in YAML format for {self.ci_platform}.
        The pipeline should build, test, and **automatically deploy** the application artifact to the target server using SSH/SCP.

        **Context:**
        - Repository URL: {self.repo_url}
        - Detected Technology Stack: {self.detected_stack}
        - Cloud Provider: {self.cloud_provider}
        - Deployment Target Type: {target_type}
        - **Deployment Server IP:** {deploy_ip}
        - **Deployment SSH User:** {deploy_user}
        - **CI/CD Secret Name for SSH Key:** {ssh_secret_name} (This secret must contain the private SSH key and be configured in the CI/CD platform settings)
        - **Build Artifact Name:** {artifact_name}
        - **Assumed Deployment Script on Server:** `~/deploy.sh` (This script should exist in the user's home directory on the server and handle unpacking {artifact_name}, installing dependencies, and restarting the application)

        **Pipeline Requirements:**
        1.  **Trigger:** Configure the pipeline to run on pushes to the `main` or `master` branch.
        2.  **Checkout:** Check out the repository code.
        3.  **Setup Environment:** Set up the necessary runtime environment for the `{self.detected_stack}` stack (e.g., Node.js version, Python version, Java JDK). Use common versions if not specified.
        4.  **Install Dependencies:** Run standard commands to install project dependencies (e.g., `npm install`, `pip install -r requirements.txt`, `mvn install`).
        5.  **Build (if applicable):** Run standard build commands (e.g., `npm run build`, `mvn package`). Skip if not typical for the stack (like basic Python/Node scripts).
        6.  **Test (Optional Placeholder):** Include a placeholder step for running tests (e.g., `npm test`, `python -m unittest`). It's okay if it just echoes a message if specific commands aren't known.
        7.  **Archive:** Create a deployment artifact named `{artifact_name}` containing the necessary files to run the application (e.g., built files, scripts, package.json, requirements.txt, but NOT node_modules or virtualenvs).
        8.  **Deploy (Only if target is VM-like: {is_vm_like}):**
            -   **Condition:** This step should ideally only run if the target type is VM-like (EC2, Azure VM, GCP VM). If not, skip this step gracefully.
            -   **Add SSH Key:** Securely load the private key from the `{ssh_secret_name}` secret into the SSH agent or a temporary file recognized by SSH/SCP commands. Handle permissions correctly (chmod 600).
            -   **SCP Artifact:** Use `scp` to copy the `{artifact_name}` to the server's home directory (`~`). Use appropriate flags like `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` for simplicity in a CI environment (acknowledge security implications if possible in comments).
            -   **Execute Remote Script:** Use `ssh` to connect to the server (using the loaded key, user `{deploy_user}`, and IP `{deploy_ip}`) and execute the deployment script: `bash ~/deploy.sh`. Again, use appropriate flags like `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`.
        9.  **Platform Specifics:** Use syntax and recommended actions/plugins appropriate for `{self.ci_platform}` (e.g., `actions/checkout@v3`, `actions/setup-node@v3`, `${{{{ secrets.{ssh_secret_name} }}}}` for GitHub Actions).

        **Output:**
        Generate **only** the complete and valid YAML configuration content. Do not include any explanations, markdown formatting (like ```yaml), or introductory sentences outside the YAML structure itself.
        """

# logger.debug(f"Refined LLM Prompt (Truncated):\n{prompt[:800]}...") # Optional: Log more of the prompt if needed
        logger.debug(f"LLM Prompt (Truncated):\n{prompt[:600]}...")

        try:
            logger.info("Sending request to OpenAI API...")
            # ... (Keep OpenAI API call logic) ...
            response = self.openai_client.chat.completions.create(
                model="gpt-4o", # Or gpt-4 if available/needed
                messages=[
                    {"role": "system", "content": f"You are a DevOps assistant generating {self.ci_platform} YAML configuration for automated application deployment to a server via SSH/SCP."},
                    {"role": "user", "content": prompt}],
                temperature=0.2
            )
            generated_text = response.choices[0].message.content
            logger.debug("LLM Raw Response received.")
            
            yaml_start_marker = "```yaml"; yaml_end_marker = "```"
            yaml_content = None
            if yaml_start_marker in generated_text and yaml_end_marker in generated_text:
                start = generated_text.find(yaml_start_marker) + len(yaml_start_marker)
                end = generated_text.find(yaml_end_marker, start)
                yaml_content = generated_text[start:end].strip() if end != -1 else generated_text[start:].strip()
            elif generated_text.strip().startswith(('name:', 'image:', 'jobs', 'stages:', 'pipelines:', 'on:')): # Added 'on:' for GitHub
                yaml_content = generated_text.strip()
                logger.debug("Assuming raw respone is YAML content.")
            
            else:
                # Fallback: look for yaml-like indentation at the start
                 lines = generated_text.strip().splitlines()
                 if lines and (lines[0].startswith(' ') or ':' in lines[0]):
                     logger.debug("Attempting to treat raw response as YAML due to indentation/structure.")
                     yaml_content = generated_text.strip()

            if not yaml_content:
                logger.error("LLM did not return recognizable YAML content."); return False
            try:
                yaml.safe_load(yaml_content)
                logger.info("Generated YAML syntax appears valid.")
            except yaml.YAMLError as e:
                logger.error(f"Generated content is not valid YAML: {e}\n--- Content Start ---\n{yaml_content}\n--- Content End ---")
                return False
            # --- Commit or Save ---
            
            commit_message = "feat: Add AI-generated CI/CD pipeline for automated deployment"
            if self.is_github_repo:
                if not self._commit_file_via_api(target_ci_path, yaml_content, commit_message):
                    logger.error("Failed to commit automated CI/CD config via API.")
                    return False
                self.commit_pushed = True
            else:
                # Existing local save logic...
                try:
                    local_dir = os.path.dirname(target_ci_path)
                    if local_dir: os.makedirs(local_dir, exist_ok=True)
                    with open(target_ci_path, 'w') as f: f.write(yaml_content)
                    logger.info(f"Generated automated CI/CD configuration saved locally to: {target_ci_path}")
                    self._add_keys_to_gitignore_local() # Ensure keys are ignored before potential commit
                    # Note: self.commit_pushed is handled later by commit_and_push_local_changes
                except Exception as e:
                    logger.error(f"Failed to save automated CI/CD config locally: {e}", exc_info=True)
                    return False

            # New code to automate secret setup for GitHub Actions
            if self.is_github_repo and self.ssh_key_paths.get('private'):
                try:
                    # Check if PyNaCl is available before proceeding
                    if nacl is None:
                         raise ImportError("PyNaCl not installed.")

                    repo = self.repo_object
                    # Check if secret already exists (optional but good practice)
                    try:
                        repo.get_secret(ssh_secret_name)
                        logger.info(f"Secret '{ssh_secret_name}' already exists. Skipping creation.")
                        self.ssh_key_secret_set = True # Assume it's set correctly
                        return True # Skip the rest of the secret setting
                    except UnknownObjectException:
                        logger.info(f"Secret '{ssh_secret_name}' not found. Proceeding to create it.")
                    except GithubException as ge:
                         # Handle potential permission errors during check
                         if ge.status == 404: # Expected if secret doesn't exist
                              logger.info(f"Secret '{ssh_secret_name}' not found (via check). Proceeding to create it.")
                         else:
                              logger.warning(f"Could not check for existing secret '{ssh_secret_name}': {ge}. Attempting creation anyway.")

                    # Get the repository's public key for encryption
                    # Corrected: Use the authenticated PyGithub client's request method
                    # Make sure to handle potential JSON parsing errors
                    response = self.github_client.requester.requestJsonAndCheck("GET", f"/repos/{repo.full_name}/actions/secrets/public-key")
                    public_key_data = response[1] # [status_code, data]
                    key_id = public_key_data['key_id']
                    public_key_b64 = public_key_data['key']

                    # Encrypt the private key content
                    pub_key = PublicKey(public_key_b64, encoder=Base64Encoder)
                    sealed_box = SealedBox(pub_key)
                    with open(self.ssh_key_paths['private'], 'rb') as f:
                        private_key_content = f.read()

                    encrypted = sealed_box.encrypt(private_key_content) # Encrypt raw bytes
                    encrypted_value_b64 = Base64Encoder.encode(encrypted).decode('utf-8') # Encode result to Base64 string

                    # Set the secret via GitHub API
                    secret_data = {
                        "encrypted_value": encrypted_value_b64,
                        "key_id": key_id
                    }
                    # Use the authenticated PyGithub client's request method
                    self.github_client.requester.requestJsonAndCheck(
                         "PUT",
                         f"/repos/{repo.full_name}/actions/secrets/{ssh_secret_name}",
                         input=secret_data # Use 'input' for PUT body with requester
                     )
                    logger.info(f"Successfully set '{ssh_secret_name}' secret via GitHub API.")
                    self.ssh_key_secret_set = True
                except ImportError:
                    logger.warning(f"PyNaCl not installed (`pip install pynacl`). Skipping automatic SSH key secret setup. Please set {ssh_secret_name} manually in GitHub secrets.")
                    self.ssh_key_secret_set = False # Explicitly false
                except GithubException as e:
                    logger.error(f"GitHub API error setting secret '{ssh_secret_name}': {e.status} - {e.data}", exc_info=True)
                    logger.error("Ensure the PAT has 'repo' scope and Actions secrets write permissions.")
                    self.ssh_key_secret_set = False # Explicitly false
                except Exception as e:
                    logger.error(f"Failed to set {ssh_secret_name} secret: {e}", exc_info=True)
                    self.ssh_key_secret_set = False # Explicitly false
            elif not is_vm_like:
                 logger.info(f"Target type '{target_type}' does not require SSH key secret. Skipping automatic setup.")


            return True

        # ... (Keep OpenAI error handling) ...
        except openai.APIError as e: logger.error(f"OpenAI API Error: {e}"); return False
        except openai.AuthenticationError as e: logger.error(f"OpenAI Auth Error: {e}"); return False
        except openai.RateLimitError as e: logger.error(f"OpenAI Rate Limit Error: {e}"); return False
        except Exception as e: logger.error(f"LLM interaction error: {e}", exc_info=True); return False
        
    # --- Git Commit ---
    def _commit_file_via_api(self, file_path: str, content: str, message: str) -> bool:
        """Commits a file to the GitHub repository using the API."""
        if not self.repo_object:
            logger.error("Cannot commit via API: GitHub repository object not available.")
            return False
        logger.info(f"Attempting to commit file '{file_path}' via GitHub API...")
        try:
            try:
                # Check if file exists to update it, otherwise create it
                existing_file = self.repo_object.get_contents(file_path)
                logger.info(f"File '{file_path}' exists. Updating...")
                update_result = self.repo_object.update_file(
                    path=file_path,
                    message=message,
                    content=content,
                    sha=existing_file.sha
                    # branch= # Optional: specify branch if not default
                )
                commit_sha = update_result['commit'].sha
                logger.info(f"Successfully updated file '{file_path}' via API. Commit SHA: {commit_sha}")
                self.commit_pushed = True # Mark as pushed
                return True
            except UnknownObjectException:
                # File doesn't exist, create it
                logger.info(f"File '{file_path}' does not exist. Creating...")
                create_result = self.repo_object.create_file(
                    path=file_path,
                    message=message,
                    content=content
                    # branch= # Optional: specify branch if not default
                )
                commit_sha = create_result['commit'].sha
                logger.info(f"Successfully created file '{file_path}' via API. Commit SHA: {commit_sha}")
                self.commit_pushed = True # Mark as pushed
                return True
        except GithubException as e:
            logger.error(f"GitHub API error committing file '{file_path}': {e.status} - {e.data.get('message', 'Error')}")
            # Common errors: 401 (bad token), 403 (permissions), 404 (repo/branch not found), 409 (conflict - rare here), 422 (validation)
            if e.status == 409: logger.error("Conflict occurred. Maybe the file was modified concurrently?")
            if e.status == 403: logger.error("Permission denied. Does the token have 'repo' (or 'public_repo') scope?")
            self.commit_pushed = False
            return False
        except Exception as e:
            logger.error(f"Unexpected error committing file via API: {e}", exc_info=True)
            self.commit_pushed = False
            return False
        
    def _add_keys_to_gitignore_local(self):
        """Adds generated SSH keys to .gitignore in the local repo path."""
        if not self.repo_path or not os.path.isdir(self.repo_path):
            return # No local repo to modify

        gitignore_path = os.path.join(self.repo_path, '.gitignore')
        added_to_gitignore = []
        try:
            gitignore_content = ""
            if os.path.exists(gitignore_path):
                with open(gitignore_path, 'r') as f_read: gitignore_content = f_read.read()

            # Check if private key exists and needs adding
            private_key_path = self.ssh_key_paths.get('private')
            if private_key_path:
                key_file_name = os.path.basename(private_key_path)
                # Check relative path from repo root as well if key is outside
                try:
                    rel_key_path = os.path.relpath(private_key_path, self.repo_path)
                except ValueError: # Happens if keys are on different drives (Windows)
                     rel_key_path = key_file_name # Fallback to just filename

                # Add if filename or relative path not present
                if key_file_name not in gitignore_content and rel_key_path not in gitignore_content:
                     with open(gitignore_path, 'a') as f_append:
                        f_append.write(f"\n# AI DevOps Keys\n{key_file_name}\n") # Usually just add filename
                        added_to_gitignore.append(key_file_name)
                        logger.info(f"Added '{key_file_name}' to local .gitignore")
        except Exception as e:
            logger.warning(f"Could not update local .gitignore: {e}")

    def commit_and_push_local_changes(self) -> bool:
        """Commits and pushes changes from the local temporary repo."""
        if not self.repo_path or not os.path.isdir(self.repo_path):
            logger.warning("Skipping local commit/push: No local repository path."); return True # Not a failure state

        logger.info("Committing and pushing local changes...")
        # Ensure keys are in gitignore *before* adding files
        self._add_keys_to_gitignore_local()

        try:
            repo = Repo(self.repo_path)
            repo.git.add(A=True) # Add all changes (CI file, .gitignore)

            if not repo.is_dirty(untracked_files=True):
                logger.info("No local changes detected to commit.");
                self.commit_pushed = False # No push needed
                return True # Still success

            commit_message = "feat: Add AI-generated CI/CD configuration"
            # Add more details if needed, e.g., which keys were ignored
            repo.index.commit(commit_message)
            logger.info("Committed local changes.")

            # Push logic (original, adapted for clarity)
            pushed = False
            remote_name = 'origin'
            try:
                remote = repo.remote(name=remote_name)
                logger.info(f"Pushing local changes to remote '{remote_name}'...")
                # Use credentials if provided (HTTPS) or rely on SSH agent/config
                push_result = remote.push()

                # Check push_result for errors (more robust check needed depending on GitPython version)
                # Simple check: assume no exception means success for now
                pushed = True
                logger.info("Local push successful.")

            except GitCommandError as pe:
                logger.error(f"Local push failed: {pe.stderr}")
                logger.error("Please ensure your credentials (token/SSH key) are correctly configured for this repository.")
                pushed = False
            except ValueError:
                logger.error(f"Remote '{remote_name}' not found in the local repository.")
                pushed = False

            self.commit_pushed = pushed
            return True # Commit itself succeeded even if push failed

        except GitCommandError as e:
            logger.error(f"Git commit error: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected local commit/push error: {e}", exc_info=True)
            return False


    # --- Setup Instructions ---
        # --- Setup Instructions ---
        # --- Setup Instructions ---
    def generate_setup_instructions(self) -> str:
        """Generates instructions focusing on CI/CD setup and manual fallbacks."""
        instructions = ["# AI DevOps Setup & Deployment Instructions\n"]

        resource_info = self.created_resource_details or self.selected_resource_details
        target_type = self.resource_configuration.get('type', 'unknown')
        is_vm_like = target_type in ['ec2', 'vm'] # Check if it's a VM type requiring SSH/SCP
        ssh_secret_name = "DEPLOY_SSH_PRIVATE_KEY" # Standardized secret name

        # --- Section 1: Overview ---
        instructions.append("## 1. Overview")
        instructions.append("- This tool has configured cloud infrastructure and generated a CI/CD pipeline configuration.")

        commit_status = "committed to your repository" if self.commit_pushed else "saved locally (needs manual commit/push)"
        if self.ci_platform:
            instructions.append(f"- A basic {self.ci_platform} pipeline configuration (`{'.github/workflows/ai-devops-cicd.yml' or '.gitlab-ci.yml' or 'bitbucket-pipelines.yml'}`) was generated and {commit_status}.")
            if is_vm_like:
                 instructions.append(f"  - **Goal:** This pipeline aims to **automatically deploy** your application to the target server ({target_type}) on pushes to the main/master branch.")
                 instructions.append(f"  - **ACTION REQUIRED for Automation:** For automatic deployment to work, you **MUST** configure the `{ssh_secret_name}` secret in your CI/CD provider settings (e.g., GitHub Repository Secrets).")
                 instructions.append(f"    - The value of this secret must be the **entire content** of the private SSH key (`.pem` file) required to access the server.")

                 # Report on automatic secret setting attempt
                 if self.is_github_repo and self.ssh_key_paths.get('private'): # Check if script *should* have tried
                      if self.ssh_key_secret_set:
                           instructions.append(f"    - ✅ The script **successfully attempted** to set the `{ssh_secret_name}` secret automatically via the GitHub API using the generated key.")
                           instructions.append(f"    - Verify this secret in your repository's Settings > Secrets and variables > Actions.")
                      else:
                           instructions.append(f"    - ⚠️ The script **could not** automatically set the `{ssh_secret_name}` secret (requires PyNaCl library, PAT permissions, or encountered an API error).")
                           instructions.append(f"    - **You MUST set the `{ssh_secret_name}` secret manually.**")
                 elif is_vm_like: # VM-like target, but maybe existing VM or non-GitHub
                      instructions.append(f"    - **You MUST set the `{ssh_secret_name}` secret manually.**")

            else:
                 instructions.append(f"  - This pipeline is configured for the `{target_type}` target. Deployment steps may vary based on the specific service (e.g., Lambda update, ECS service update). Review the generated YAML.")

        else:
             instructions.append("- CI/CD configuration generation was skipped or failed.")

        if not self.commit_pushed and self.ci_platform:
            instructions.append(f"- **Manual Action:** Since changes were not pushed, manually review, commit, and push the generated CI/CD file and any `.gitignore` changes.")

        instructions.append("- You may need a local SSH client for manual access or troubleshooting.")

        # --- Section 2: SSH Key Details (Important for Manual Access & Secret Value) ---
        private_key_path_generated = self.ssh_key_paths.get('private')
        private_key_path_display = "N/A"
        public_key_path_display = "N/A"
        key_source_info = ""

        if private_key_path_generated:
            # Key was generated by the script for a NEW resource
            private_key_path_display = private_key_path_generated
            public_key_path_display = self.ssh_key_paths.get('public', f"{private_key_path_display}.pub")
            key_source_info = "(Generated by Script)"
            instructions.append("\n## 2. SSH Key Details " + key_source_info)
            instructions.append(f"- An SSH key pair was generated for accessing the **newly created** resource.")
            instructions.append(f"  - **Private Key File:** `{private_key_path_display}` (Located in the script's directory)")
            instructions.append(f"  - **Public Key File:** `{public_key_path_display}`")
            key_name_in_cloud = self.ssh_key_paths.get('key_name', os.path.basename(private_key_path_display).replace('.pem',''))
            instructions.append(f"  - **Key Name Reference:** `{key_name_in_cloud}` (Used during resource creation).")
            instructions.append(f"  - 🔐 **IMPORTANT:** Keep the private key file (`{os.path.basename(private_key_path_display)}`) secure. **Do not commit it to Git.**")
            instructions.append(f"  - The script attempted to add `{os.path.basename(private_key_path_display)}` to `.gitignore` {commit_status}.")
            instructions.append(f"  - **Use the content of this private key file** when setting the `{ssh_secret_name}` secret in your CI/CD platform.")
        elif is_vm_like:
            # Existing VM was selected OR key wasn't generated by this script run
            instructions.append("\n## 2. SSH Key Details (Existing VM / Manual Key)")
            instructions.append("- You selected an existing VM or the key was not generated by this script run.")
            instructions.append("- You must use the **correct existing private key** that corresponds to the public key already authorized on that VM.")
            instructions.append(f"- **Action Required:** Locate your existing private key file.")
            private_key_path_display = "/path/to/your/existing_private_key.pem" # Placeholder
            instructions.append(f"- **Use the content of this existing private key file** when setting the `{ssh_secret_name}` secret in your CI/CD platform.")


        # --- Section 3: Triggering Deployment & Manual Fallback ---
        instructions.append("\n## 3. Deployment")
        instructions.append("\n### 3.1 Automated Deployment (Recommended)")
        instructions.append(f"1.  **Ensure Secret is Set:** Verify the `{ssh_secret_name}` secret is correctly configured in your CI/CD platform (see Section 1).")
        if not self.commit_pushed and self.ci_platform:
                     target_ci_path = target_ci_path if 'target_ci_path' in locals() else 'pipeline.yml'
                     instructions.append(f"2.  **Push Changes:** Manually commit and push the CI/CD configuration file (`{target_ci_path}`) and any other changes to your `main` or `master` branch.")
        else:
            instructions.append(f"2.  **Trigger Pipeline:** Push a commit to your `main` or `master` branch.")
        instructions.append(f"3.  **Monitor Pipeline:** Check the execution status and logs in your {self.ci_platform} interface.")

        if is_vm_like:
            instructions.append("\n### 3.2 Manual Deployment (Fallback / Testing)")
            instructions.append("If automated deployment fails or you need to deploy manually:")
            ssh_user = resource_info.get('ssh_user') or resource_info.get('admin_username', 'YOUR_SSH_USER')
            public_ip = resource_info.get('public_ip', 'YOUR_SERVER_IP')

            if public_ip == 'N/A' or public_ip == 'YOUR_SERVER_IP' or not public_ip:
                 instructions.append("- ⚠️ Could not determine the Public IP address. Find it in your cloud provider console.")
                 public_ip = "YOUR_SERVER_IP" # Reset placeholder
            if ssh_user == 'N/A' or ssh_user == 'YOUR_SSH_USER' or not ssh_user:
                 instructions.append("- ⚠️ Could not determine the SSH username. Common defaults: `ubuntu`, `ec2-user` (AWS), `azureuser` (Azure). Find the correct one.")
                 ssh_user = "YOUR_SSH_USER" # Reset placeholder

            instructions.append(f"1.  **Locate Your Private Key:** `{private_key_path_display}` (Replace with your actual key path).")
            instructions.append(f"2.  **(Optional) Set Permissions:** On Linux/macOS: `chmod 600 {private_key_path_display}`")
            instructions.append(f"3.  **Build Artifact:** Create the deployment artifact locally (e.g., `app.zip` containing your application files). The exact steps depend on your stack.")
            instructions.append(f"4.  **Copy Artifact:** Use `scp`:")
            instructions.append(f"    ```bash")
            instructions.append(f"    scp -i {private_key_path_display} ./app.zip {ssh_user}@{public_ip}:~/")
            instructions.append(f"    ```")
            instructions.append(f"5.  **SSH and Deploy:** Connect and run deployment steps:")
            instructions.append(f"    ```bash")
            instructions.append(f"    ssh -i {private_key_path_display} {ssh_user}@{public_ip} 'bash ~/deploy.sh'")
            instructions.append(f"    ```")
            instructions.append(f"    (Ensure `~/deploy.sh` exists on the server and does what's needed).")

        # --- Section 4: Next Steps ---
        instructions.append("\n## 4. Next Steps & Troubleshooting")
        instructions.append("- **Create `deploy.sh`:** If you haven't already, create the `deploy.sh` script in the home directory (`~/`) on your target server. This script should handle:")
        instructions.append("  - Unpacking the artifact (e.g., `unzip -o app.zip -d /path/to/app`)")
        instructions.append("  - Navigating to the application directory (`cd /path/to/app`)")
        instructions.append("  - Installing/updating dependencies (e.g., `npm install --production`, `pip install -r requirements.txt`)")
        instructions.append("  - Building if necessary (e.g., `npm run build`)")
        instructions.append("  - Restarting your application (e.g., `pm2 reload app_name`, `systemctl restart your_service`)")
        instructions.append("- **Check Pipeline Logs:** Carefully review the CI/CD pipeline logs for any errors during build or deployment steps.")
        instructions.append("- **Check Server Logs:** If deployment succeeds but the app doesn't work, check application logs on the server.")
        if not is_vm_like and target_type != 'unknown':
            instructions.append(f"- **Consult Cloud Provider Docs:** Review documentation for deploying to {self.cloud_provider.upper()} {target_type} if the generated pipeline needs adjustments.")

        return "\n".join(instructions)
    # --- Cleanup ---
    def cleanup(self):
        """Cleans up the temporary local repository if it was created."""
        if self.repo_path and os.path.isdir(self.repo_path):
            logger.info(f"Cleaning up temporary local directory: {self.repo_path}")
            try:
                shutil.rmtree(self.repo_path, onerror=remove_readonly)
                logger.info(f"Successfully cleaned up {self.repo_path}")
                self.repo_path = None
            except Exception as e:
                logger.error(f"Error removing temporary directory {self.repo_path}: {e}")
        else:
            logger.debug("Skipping cleanup: No temporary local repository path set.")


    # --- Run Method ---
    def run(self, args: argparse.Namespace): # Accept args
        """Run the entire workflow"""
        self.commit_pushed = False # Reset push status
        try:
            logger.info("Starting AI DevOps Automator run...")
            if not self.collect_git_credentials(): return "Failed to collect Git credentials."

            # Access repo & Detect Stack (API or Clone)
            if not self.access_repository_and_detect_stack():
                 self.cleanup(); return "Failed to access repository or detect stack."

            # Cloud Config & Creation (No change needed here)
            if not self.collect_cloud_credentials(): self.cleanup(); return "Failed to collect cloud credentials."
            if not self.configure_cloud_resource(): self.cleanup(); return "Failed to configure cloud resource target."

            if self.resource_configuration.get('create_new', False):
                 logger.info("Initiating creation of NEW cloud resource...")
                 create_success = False # ... (Keep the existing resource creation logic) ...
                 res_type = self.resource_configuration.get('type')
                 try:
                      # Simplified calls using instance attributes where possible
                      if self.cloud_provider == 'aws':
                           session = self._get_aws_session()
                           if not session: raise Exception("Failed to get AWS session for creation")
                           if res_type == 'ec2': create_success = self._create_aws_ec2_instance(session.client('ec2'))
                           elif res_type == 'ecs': create_success = self._create_aws_ecs_cluster(session.client('ecs'))
                           elif res_type == 'lambda': create_success = self._create_aws_lambda_function(session.client('lambda'), session.client('iam'))
                      elif self.cloud_provider == 'azure':
                           cred = self._get_azure_credential()
                           sub_id = self.cloud_credentials.get('subscription_id')
                           if not cred or not sub_id: raise Exception("Failed to get Azure credentials for creation")
                           if res_type == 'vm': create_success = self._create_azure_vm(azure.mgmt.compute.ComputeManagementClient(cred, sub_id), azure.mgmt.network.NetworkManagementClient(cred, sub_id), azure.mgmt.resource.ResourceManagementClient(cred, sub_id))
                           # Add App Service creation if desired
                      elif self.cloud_provider == 'gcp':
                           cred, proj_id = self._get_gcp_credential()
                           if not cred or not proj_id: raise Exception("Failed to get GCP credentials for creation")
                           if res_type == 'vm': create_success = self._create_gcp_vm(compute_v1.InstancesClient(credentials=cred), cred, proj_id)
                           # Add Cloud Run creation if desired

                      if not create_success: raise Exception(f"Creation function for {res_type} returned False or not implemented.")
                      logger.info(f"Successfully created NEW {res_type} resource.")
                 except Exception as creation_e:
                      logger.error(f"Error during explicit resource creation: {creation_e}", exc_info=True)
                      self.cleanup(); return "Failed during resource creation phase."
            else: logger.info("Skipping resource creation (existing resource selected).")

            # Generate CI/CD (and commit via API if applicable)
            if not self.generate_cicd_config():
                 # If API commit failed, self.commit_pushed is false
                 # If local save failed, it returns false
                 logger.error("Failed to generate and save/commit CI/CD configuration.")
                 self.cleanup(); return "Failed to generate/commit CI/CD configuration."

            # Commit/Push local changes (only if not using GitHub API)
            if not self.is_github_repo:
                 if not self.commit_and_push_local_changes():
                      # commit_pushed will be false, instructions will guide user
                      logger.warning("Failed to commit or push local changes. Check instructions.")

            # Deployment Explanation
            logger.info("="*30 + " DEPLOYMENT NOTE " + "="*30)
            logger.info("Infrastructure and CI/CD pipeline setup is complete.")
            logger.info("The actual deployment of your application code will be handled by the")
            logger.info(f"'{self.ci_platform}' pipeline generated in your repository.")
            logger.info("Trigger the pipeline (e.g., by pushing to main/master) and monitor its execution.")
            logger.info("Ensure you have configured the required secrets (cloud credentials, SSH keys) in your CI/CD provider settings.")
            logger.info("="*77)


            # Generate final instructions
            setup_instructions = self.generate_setup_instructions()
            return setup_instructions

        except Exception as e:
             logger.error(f"An unexpected error occurred in the main workflow: {e}", exc_info=True)
             self.cleanup(); return f"An unexpected error occurred: {e}"
        finally:
             # Cleanup Logic (only cleans local repo if it exists)
             if self.is_github_repo:
                  logger.debug("Running in GitHub API mode, skipping local repo cleanup check.")
             else:
                  # Original cleanup logic based on local repo state and flags
                  commit_failed_or_not_pushed = not getattr(self, 'commit_pushed', False)
                  if self.repo_path and os.path.isdir(self.repo_path):
                      if commit_failed_or_not_pushed and not args.cleanup_repo:
                          logger.warning(f"Local commit/push failed or skipped. Temporary repository left at: {self.repo_path}")
                      elif args.cleanup_repo:
                          logger.info("Force cleanup requested via flag.")
                          self.cleanup()
                      elif not commit_failed_or_not_pushed:
                          logger.info("Workflow finished successfully. Cleaning up temporary repository...")
                          self.cleanup()


# --- Main Function ---
def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='AI DevOps Tool - CI/CD & Cloud Resources.')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--cleanup-repo', action='store_true', help='Force cleanup of temp repo')
    args = parser.parse_args() # Parse args here

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG); logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    if not os.environ.get("OPENAI_API_KEY"):
         print("="*80 + "\n⚠️ WARNING: OPENAI_API_KEY not set. AI features disabled.\n" + "="*80)

    print("="*80 + "\n🤖 Welcome to AI DevOps Automation Tool! 🤖\n" + "="*80)

    automator = AIDevOpsAutomator()
    result = automator.run(args) # Pass args to run method

    print("\n" + "="*80 + "\n✨ Automation Result ✨\n" + "="*80)
    print(result)
    print("="*80)

# --- Required libraries check ---
if __name__ == "__main__":
    missing_libs = []
    try: import git
    except ImportError: missing_libs.append("GitPython")
    try: import yaml
    except ImportError: missing_libs.append("PyYAML")
    try: import boto3
    except ImportError: missing_libs.append("boto3")
    try: import azure.identity
    except ImportError: missing_libs.append("azure-identity")
    try: import azure.mgmt.resource
    except ImportError: missing_libs.append("azure-mgmt-resource")
    try: import azure.mgmt.compute
    except ImportError: missing_libs.append("azure-mgmt-compute")
    try: import azure.mgmt.network
    except ImportError: missing_libs.append("azure-mgmt-network")
    try: import google.cloud.compute_v1 # Check specific client
    except ImportError: missing_libs.append("google-cloud-compute")
    try: import google.auth
    except ImportError: missing_libs.append("google-auth")
    try: import cryptography
    except ImportError: missing_libs.append("cryptography")
    try: import openai
    except ImportError: missing_libs.append("openai")
    try: import github # Check PyGithub
    except ImportError: missing_libs.append("PyGithub") # Add PyGithub
    try: import nacl
    except ImportError: missing_libs.append("pynacl")
    # Rest of the existing checks...

    if missing_libs:
        print(f"Error: Missing required Python package(s): {', '.join(missing_libs)}")
        print("Please install them (e.g., using pip install ...)")
        # Suggest specific install command
        print(f"Example: pip install {' '.join(missing_libs)}")
        exit(1) 

    main()
# --- END OF FILE llm.py ---