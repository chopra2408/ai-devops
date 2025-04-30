import os
import getpass  
import yaml
import tempfile
import json
from git import Repo, GitCommandError
from typing import List, Optional, Tuple, Dict, Any
import logging
import shutil
import stat
import time
import uuid
import asyncio
from fastapi import FastAPI, HTTPException, Body, Path
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, SecretStr
from enum import Enum
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import azure.identity
import azure.mgmt.resource
import azure.mgmt.compute
import azure.mgmt.network
from azure.core.exceptions import ResourceNotFoundError as AzureResourceNotFoundError
from google.cloud import compute_v1
from google.oauth2 import service_account
import google.auth 
import google.auth.exceptions 
from google.api_core import exceptions as google_exceptions
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
import openai
try:
    from github import Github, GithubException, UnknownObjectException
except ImportError:
    Github = None

try:
    import nacl
    from nacl.public import SealedBox, PublicKey
    from nacl.encoding import Base64Encoder
except ImportError:
    nacl = None
    
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s')
logger = logging.getLogger('ai-devops-api.logic')  
api_logger = logging.getLogger('ai-devops-api.service')  

def generate_ssh_key_pair(key_filename_base="ai-devops-key"):
    """
    Generates or ensures an RSA SSH key pair exists locally.
    If private key exists but public is missing, regenerates public key.
    Returns private key path, public key content (str), key name base, and the temp directory path.
    Saves keys to a temporary directory for API context.
    """
    temp_key_dir = tempfile.mkdtemp(prefix="ai-devops-keys-")
    private_key_path = os.path.join(temp_key_dir, f"{key_filename_base}.pem")
    public_key_path = os.path.join(temp_key_dir, f"{key_filename_base}.pub")
    public_key_content = None

    logger.info(f"Generating new SSH key pair: {key_filename_base} in {temp_key_dir}")
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
            # On Linux/macOS, set 600 permissions. Windows doesn't have direct equivalent easily.
            os.chmod(private_key_path, stat.S_IREAD | stat.S_IWRITE)
            logger.info(f"Private key saved to: {private_key_path} (Basic permissions set)")
        except OSError:
            logger.warning(f"Private key saved to: {private_key_path} (Could not set restrictive permissions)")
        with open(public_key_path, "wb") as f: f.write(public_key_ssh)
        logger.info(f"Public key saved to: {public_key_path}")
        public_key_content = public_key_ssh.decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to generate new key pair: {e}", exc_info=True)
        try: shutil.rmtree(temp_key_dir)
        except Exception as cleanup_e: logger.error(f"Error cleaning up key directory {temp_key_dir}: {cleanup_e}")
        return None, None, None, None # Return None for temp_dir too

    if not public_key_content:
        logger.error("Failed to obtain public key content.")
        try: shutil.rmtree(temp_key_dir)
        except Exception as cleanup_e: logger.error(f"Error cleaning up key directory {temp_key_dir}: {cleanup_e}")
        return None, None, None, None # Return None for temp_dir too

    return private_key_path, public_key_content, key_filename_base, temp_key_dir

def remove_readonly(func, path, exc_info):
    """ Error handler for shutil.rmtree. Tries to fix permissions. """
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
        else:
            exc_type, exc_value, tb = exc_info
            logger.error(f"Cleanup error on {path} not related to read-only permissions: {exc_value}")
            
class AIDevOpsAutomator:
    def __init__(self):
        self.repo_url = None
        self.git_token = None # Store token temporarily if needed
        self.repo_path = None # Path to temp local clone if used
        self.cloud_provider = None
        self.cloud_credentials = {} # Store credentials temporarily
        self.detected_stack = None
        self.resource_configuration = {}
        self.created_resource_details = {}
        self.selected_resource_details = {}
        self.ssh_key_paths = {} # Store paths { 'private': ..., 'public': ..., 'key_name': ..., 'temp_dir': ... }
        self.ci_platform = None
        self.openai_client = None
        self.github_client = None
        self.is_github_repo = False
        self.repo_object = None
        self.ssh_key_secret_set = False
        self.commit_pushed = False # Track commit status
        
        # Initialize OpenAI Client (Consider making API key injectable)
        try:
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key:
                logger.warning("OPENAI_API_KEY environment variable not set. LLM features will be disabled.")
            else:
                # Ensure openai library was imported successfully before using it
                if 'openai' in globals() and openai is not None:
                    self.openai_client = openai.OpenAI(api_key=api_key)
                    logger.info("OpenAI client initialized.")
                else:
                    logger.error("OpenAI library import failed earlier or library not found. Cannot initialize client.")
                    self.openai_client = None

        except ImportError:
            logger.warning("OpenAI library not found (`pip install openai`). LLM features disabled.")
            self.openai_client = None
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            self.openai_client = None

        
    # Step 1: Set Git Info (replaces collect_git_credentials)
    def set_git_info(self, repo_url: str, git_token: Optional[str] = None) -> bool:
        logger.info(f"Setting Git info: URL={repo_url}, Token Provided: {'Yes' if git_token else 'No'}")
        self.repo_url = repo_url
        # Use the actual token value if provided, not just the SecretStr object
        self.git_token = git_token.get_secret_value() if isinstance(git_token, SecretStr) else git_token

        if not self.repo_url:
            logger.error("Repository URL cannot be empty")
            return False
        
        # Simplified GitHub check for API usage possibility
        if self.repo_url.startswith("https://github.com/"):
            self.is_github_repo = True
            logger.info("GitHub repository detected. Will attempt API interaction if token is provided.")
            if not self.git_token:
                logger.warning("GitHub HTTPS URL detected, but no token provided. API interactions (commit, secret set) will fail.")
            else:
                # Initialize GitHub client immediately if token is present
                try:
                    # Ensure PyGithub is imported
                    if Github is None:
                        raise ImportError("PyGithub is required for GitHub API interaction but not installed.")
                    self.github_client = Github(self.git_token)
                    user = self.github_client.get_user() # Test authentication
                    logger.info(f"Successfully authenticated with GitHub API as user: {user.login}")
                    # Get repo object early if possible
                    self._get_github_repo_object() # Try to get repo object now
                except GithubException as e:
                    logger.error(f"GitHub API authentication failed: {e.status} - {e.data.get('message', 'Unknown error')}")
                    logger.error("Please ensure the provided token is valid and has the 'repo' scope.")
                    self.github_client = None # Invalidate client
                    self.is_github_repo = False # Cannot use API features
                    logger.warning("Falling back to clone-based operations due to GitHub auth failure.")
                    # Don't return False here, allow fallback to clone
                except ImportError as e:
                    logger.error(f"{e}")
                    self.github_client = None
                    self.is_github_repo = False
                    logger.warning("Falling back to clone-based operations.")
                except Exception as e:
                    logger.error(f"Unexpected error initializing GitHub client: {e}", exc_info=True)
                    self.github_client = None
                    self.is_github_repo = False
                    logger.warning("Falling back to clone-based operations.")

        else:
            self.is_github_repo = False
            logger.info("Non-GitHub URL or SSH URL detected. Using local clone method.")
            # No need to prompt for token here, rely on provided `git_token` if needed for clone

        return True
    
    def _get_github_repo_object(self) -> bool:
        """Gets the PyGithub Repository object. Should only be called if is_github_repo and github_client are valid."""
        if not self.is_github_repo or not self.github_client:
            logger.debug("Skipping GitHub repo object fetch: Not a GitHub repo or client not available.")
            return False

        if self.repo_object: # Already fetched
            return True

        # Extract repo name (safer parsing)
        repo_full_name = None
        if self.repo_url.startswith("https://github.com/"):
            parts = self.repo_url.split('/')
            if len(parts) >= 5:
                repo_full_name = f"{parts[3]}/{parts[4].replace('.git','')}"

        if not repo_full_name:
            logger.error(f"Could not extract valid GitHub repository name from URL: {self.repo_url}")
            return False

        try:
            self.repo_object = self.github_client.get_repo(repo_full_name)
            logger.info(f"Successfully obtained GitHub repository object for: {repo_full_name}")
            return True
        except UnknownObjectException:
            logger.error(f"Repository '{repo_full_name}' not found or token lacks permission.")
            self.repo_object = None # Ensure it's None on failure
            return False
        except GithubException as e:
            logger.error(f"Failed to get repository object: {e.status} - {e.data.get('message', 'Unknown error')}")
            self.repo_object = None
            return False
        except Exception as e:
            logger.error(f"Unexpected error getting GitHub repo object: {e}", exc_info=True)
            self.repo_object = None
            return False
        
    def access_repository_and_detect_stack(self) -> bool:
        """
        Accesses repository files (via API for GitHub, clone otherwise)
        and detects the tech stack.
        """
        if self.is_github_repo and self.github_client: # Ensure client is valid too
            # Make sure repo object is available
            if not self.repo_object and not self._get_github_repo_object():
                logger.warning("Could not get GitHub repo object. Falling back to clone method.")
                self.is_github_repo = False # Force clone if API object fails
                return self._access_repository_via_clone()
            # Proceed with API detection if repo object is valid
            if self.repo_object:
                return self._detect_stack_via_api()
            else: # Should not happen if _get_github_repo_object worked, but safety check
                logger.warning("GitHub repo object unexpectedly missing after check. Falling back to clone method.")
                self.is_github_repo = False
                return self._access_repository_via_clone()

        else:
            # Use the original clone-based method
            logger.info("Using local clone method for stack detection.")
            return self._access_repository_via_clone()
        
    def _detect_stack_via_api(self) -> bool:
        """Detects stack by listing root files using GitHub API."""
        logger.info("Detecting technology stack via GitHub API...")
        if not self.repo_object:
            logger.error("GitHub repository object not available for API stack detection.")
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
            self.detected_stack = 'unknown' # Set to unknown on error
            return False
        
    def _access_repository_via_clone(self) -> bool:
        logger.info(f"Accessing repository via local clone: {self.repo_url}")
        # Clean up previous clone path if exists
        if self.repo_path and os.path.isdir(self.repo_path):
            logger.warning(f"Previous temporary repo path found ({self.repo_path}). Cleaning up before new clone.")
            self.cleanup() # Use the main cleanup method

        try:
            temp_dir = tempfile.mkdtemp(prefix="ai-devops-repo-")
            self.repo_path = temp_dir
            logger.info(f"Cloning repository into temporary directory: {self.repo_path}")

            clone_url = self.repo_url
            env = os.environ.copy()
            # Use self.git_token (which is now the plain string)
            if self.git_token and self.repo_url.startswith("https://"):
                # Logic for authenticated HTTPS clone using the token
                if "@" in self.repo_url.split("://")[1]: # Handle user@host format
                    proto, rest = self.repo_url.split("://")
                    # Assume token replaces password here
                    user = rest.split('@', 1)[0]
                    host_path = rest.split('@', 1)[-1]
                    # Use token as password
                    clone_url = f"{proto}://{user}:{self.git_token}@{host_path}"
                    logger.debug("Using authenticated URL (user:token@host) for clone.")
                else: # Handle standard https://host/path format
                    clone_url = self.repo_url.replace('https://', f'https://oauth2:{self.git_token}@')
                    logger.debug("Using authenticated URL (oauth2:token@host) for clone.")
                # Mask token in log output
                log_url = clone_url.replace(self.git_token, '***TOKEN***')
                logger.debug(f"Clone URL for GitPython: {log_url}")
            elif not self.git_token and "@" in self.repo_url and ":" in self.repo_url:
                 # SSH URL format
                 logger.info("Attempting clone using SSH protocol. Ensure your local SSH key is configured correctly.")
                 # GitPython will use system's SSH agent/config
            elif self.git_token:
                 logger.warning("Git token provided but URL is not HTTPS. Token will not be used for clone.")


            Repo.clone_from(clone_url, self.repo_path, env=env, depth=1) # Use shallow clone
            logger.info(f"Repository cloned successfully (shallow) to {self.repo_path}")

            # Detect stack from local files
            if not self._detect_stack_from_local_dir(): # Use helper
                # Cleanup happens in the calling function (execute_workflow) or via explicit cleanup call
                return False # Detection failed

            return True
        except GitCommandError as e:
            stderr = e.stderr.strip()
            logger.error(f"Git error during clone: {stderr}")
            if "Authentication failed" in stderr:
                logger.error("Authentication failed. Check repository URL and token/SSH key permissions.")
            # Cleanup happens in the calling function (execute_workflow) or via explicit cleanup call
            return False
        except Exception as e:
            logger.error(f"Unexpected error accessing repository via clone: {e}", exc_info=True)
            # Cleanup happens in the calling function (execute_workflow) or via explicit cleanup call
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
            logger.debug(f"Files found in local repo root: {files}")
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
        stack = 'unknown' # Default to unknown
        # Order checks can matter if multiple files exist
        if 'pom.xml' in files or 'build.gradle' in files or 'build.gradle.kts' in files: stack = 'java'
        elif 'package.json' in files: stack = 'nodejs'
        elif 'requirements.txt' in files or 'setup.py' in files or 'Pipfile' in files or 'pyproject.toml' in files: stack = 'python'
        elif 'go.mod' in files: stack = 'golang'
        elif any(f.endswith('.csproj') for f in files) or 'project.json' in files: stack = 'dotnet'
        elif 'composer.json' in files: stack = 'php'
        elif 'Cargo.toml' in files: stack = 'rust'
        # Dockerfile check last - only if no other specific stack identified
        elif 'Dockerfile' in files:
            stack = 'docker'
            logger.info("Detected Dockerfile as primary stack indicator.")

        if stack == 'unknown':
            logger.warning("Could not determine technology stack from common files.")
        elif 'Dockerfile' in files and stack != 'docker':
            logger.info(f"Detected stack '{stack}' along with a Dockerfile. Keeping primary stack '{stack}'.")

        return stack
    
    # Step 3: Set Cloud Info
    def set_cloud_info(self, provider: str, credentials: dict) -> bool:
        # Log received data right at the start of the method
        logger.info(f"Automator.set_cloud_info received: provider='{provider}', credentials={credentials}") # Log raw credentials received

        provider = provider.lower()
        if provider not in ['aws', 'azure', 'gcp']:
            # Log the specific failure reason
            logger.error(f"Validation Failed: Invalid cloud provider '{provider}' received.")
            return False

        # Log safely for general logs (avoid secrets)
        log_creds = {}
        for k, v in credentials.items():
            if any(secret_key in k.lower() for secret_key in ['secret', 'token', 'password', 'key']):
                log_creds[k] = "***SECRET***"
            else:
                log_creds[k] = v
        logger.debug(f"Processing safe credentials structure: {log_creds}")

        # Store credentials (as received)
        self.cloud_credentials = {}
        for k, v in credentials.items():
            self.cloud_credentials[k] = v
        logger.debug(f"Internal self.cloud_credentials stored: {self.cloud_credentials}") # Log the stored dict
        # Check required fields based on provider and the 'type' within credentials
        cred_type = self.cloud_credentials.get('type')
        if not cred_type:
            logger.error("Validation Failed: 'type' key missing within credentials dictionary.")
            return False  

        if provider == 'aws':
            if cred_type == 'keys':
                # Check for the keys actually used by _get_aws_session
                access_key_id_exists = self.cloud_credentials.get('access_key_id')
                secret_access_key_exists = self.cloud_credentials.get('secret_access_key')
                # region_exists = self.cloud_credentials.get('region') # Region check can be optional here

                # Use the corrected keys in the check
                if not access_key_id_exists or not secret_access_key_exists:
                    # Update error message to reflect the actual keys checked
                    logger.error("Validation Failed: AWS Keys type selected, but 'access_key_id' or 'secret_access_key' missing or empty.")
                    return False
            elif cred_type == 'assume_role':
                if not self.cloud_credentials.get('role_arn'):
                    logger.error("Validation Failed: AWS AssumeRole selected, but 'role_arn' missing/null.")
                    return False
                if not self.cloud_credentials.get('region'):
                    logger.error("Validation Failed: AWS AssumeRole selected, but 'region' is missing/null.")
                    return False
                base_type = self.cloud_credentials.get('base_type')
                if base_type == 'keys' and (not self.cloud_credentials.get('base_access_key') or not self.cloud_credentials.get('base_secret_key')):
                    logger.error("Validation Failed: AWS AssumeRole (Base Keys) selected, but 'base_access_key' or 'base_secret_key' missing/null.")
                    return False
                 
        elif provider == 'azure':
            # Subscription ID is always required for Azure in this implementation
            if not self.cloud_credentials.get('subscription_id'):
                logger.error("Validation Failed: Azure provider selected, but 'subscription_id' is missing/null.")
                return False
            # Check specific types
            if cred_type == 'service_principal':
                if not self.cloud_credentials.get('tenant_id') or not self.cloud_credentials.get('client_id') or not self.cloud_credentials.get('client_secret'):
                    logger.error("Validation Failed: Azure SP selected, but 'tenant_id', 'client_id', or 'client_secret' missing/null.")
                    return False
            # No specific required fields needed for CLI or Managed Identity beyond subscription_id (already checked)

        elif provider == 'gcp':
            # Project ID is always required for GCP
            if not self.cloud_credentials.get('project_id'):
                logger.error("Validation Failed: GCP provider selected, but 'project_id' is missing/null.")
                return False
            # Check specific types
            if cred_type == 'service_account':
                if not self.cloud_credentials.get('key_file'): # Matches the key used in _get_gcp_credential
                    logger.error("Validation Failed: GCP SA Key selected, but 'key_file' path missing/null.")
                    return False
            # No specific required fields needed for ADC beyond project_id (already checked)
        self.cloud_provider = provider # Set the provider attribute on the instance
        logger.info(f"Cloud provider '{provider}' set on automator instance. Credentials structure validated.")

        return True # Returns True only if all checks pass

    def _get_aws_session(self) -> Optional[boto3.Session]:
        """Initializes and returns a boto3 Session based on stored credentials."""
        creds = self.cloud_credentials
        session_params = {}
        # Use region from creds if provided, otherwise try boto default, else fallback
        region = creds.get('region')
        if not region:
            try: region = boto3.Session().region_name # Try default session region
            except Exception: pass
        if not region and creds.get('type') == 'profile':
            try:
                profile = creds.get('profile', 'default') # Use 'default' if profile name missing
                region = boto3.Session(profile_name=profile).region_name
            except Exception: pass # Ignore errors getting region from profile
        if region:
            session_params['region_name'] = region
        else:
            session_params['region_name'] = 'us-east-1'; # Last resort fallback
            logger.warning(f"Could not determine AWS region. Defaulting to {session_params['region_name']}.")

        # Update stored creds with the region actually being used
        self.cloud_credentials['region'] = session_params['region_name']
        creds = self.cloud_credentials # Re-assign creds as it might have been updated

        try:
            cred_type = creds.get('type')
            if cred_type == 'profile':
                profile_name = creds.get('profile', 'default') # Default profile if not specified
                session_params['profile_name'] = profile_name
                logger.info(f"Using AWS profile: {profile_name} in region {session_params['region_name']}")
                # Test credentials early
                boto3.Session(**session_params).client('sts').get_caller_identity()
                return boto3.Session(**session_params)
            elif cred_type == 'keys':
                # Check if keys exist (should have been validated in set_cloud_info)
                if not creds.get('access_key') or not creds.get('secret_key'):
                    logger.error("AWS Keys missing for session creation.")
                    return None
                logger.info(f"Using AWS access keys in region {session_params['region_name']}")
                session_params['aws_access_key_id'] = creds.get('access_key')
                session_params['aws_secret_access_key'] = creds.get('secret_key')
                # Test credentials early
                boto3.Session(**session_params).client('sts').get_caller_identity()
                return boto3.Session(**session_params)
            elif cred_type == 'assume_role':
                logger.info(f"Attempting to assume role: {creds.get('role_arn')}")
                # Base session parameters depend on base_type
                base_session_params = {'region_name': session_params['region_name']}
                base_type = creds.get('base_type')
                base_session = None
                if base_type == 'profile':
                    base_profile = creds.get('base_profile', 'default')
                    base_session_params['profile_name'] = base_profile
                    logger.info(f"Using base profile '{base_profile}' for AssumeRole.")
                    base_session = boto3.Session(**base_session_params)
                elif base_type == 'keys':
                    if not creds.get('base_access_key') or not creds.get('base_secret_key'):
                        logger.error("Base AWS Keys missing for AssumeRole.")
                        return None
                    base_session_params['aws_access_key_id'] = creds.get('base_access_key')
                    base_session_params['aws_secret_access_key'] = creds.get('base_secret_key')
                    logger.info("Using base keys for AssumeRole.")
                    base_session = boto3.Session(**base_session_params)
                else:
                    logger.error(f"Invalid base credential type '{base_type}' for assume role."); return None

                # Test base credentials before assuming role
                base_session.client('sts').get_caller_identity()

                sts_client = base_session.client('sts')
                role_arn = creds.get('role_arn')
                session_name = creds.get('session_name', 'ai-devops-api-session') # Default session name
                if not role_arn:
                    logger.error("Role ARN is missing for AssumeRole.")
                    return None

                assumed_role_object = sts_client.assume_role(
                      RoleArn=role_arn, RoleSessionName=session_name
            )
                assumed_creds = assumed_role_object['Credentials']
                logger.info(f"Successfully assumed role {role_arn}")
                 # Return session using assumed credentials
                return boto3.Session(
                    aws_access_key_id=assumed_creds['AccessKeyId'],
                    aws_secret_access_key=assumed_creds['SecretAccessKey'],
                    aws_session_token=assumed_creds['SessionToken'],
                    region_name=session_params['region_name']
                )
            else:
                logger.error(f"Unsupported AWS credential type: {cred_type}"); return None
        except (ClientError, NoCredentialsError) as e:
            # Provide more context for common errors
            error_code = e.response.get('Error', {}).get('Code', 'Unknown') if hasattr(e, 'response') else 'Unknown'
            logger.error(f"AWS credential/API error ({error_code}): {e}")
            if error_code == 'ExpiredToken': logger.error("AWS token has expired.")
            elif error_code == 'InvalidClientTokenId' or error_code == 'SignatureDoesNotMatch': logger.error("Invalid AWS Access Key ID or Secret Key.")
            elif error_code == 'AccessDenied': logger.error("AWS Permissions error. Ensure the credentials have necessary permissions (e.g., STS GetCallerIdentity, EC2 Describe*, etc.).")
            return None
        except Exception as e:
            logger.error(f"Failed to create AWS session: {e}", exc_info=True); return None
            
    def _get_azure_credential(self) -> Optional[Any]: # Return type can vary (TokenCredential subclasses)
         """Gets the appropriate Azure credential object."""
         creds = self.cloud_credentials
         credential = None
         try:
              cred_type = creds.get('type')
              if cred_type == 'cli':
                   logger.info("Using Azure CLI credential.")
                   # Check if Azure CLI is installed and logged in (best effort)
                   try:
                        credential = azure.identity.AzureCliCredential()
                        credential.get_token("https://management.azure.com/.default") # Test token acquisition
                        logger.info("Azure CLI credential obtained successfully.")
                   except Exception as cli_err:
                        logger.error(f"Failed to get token using Azure CLI credential: {cli_err}. Is Azure CLI installed and are you logged in (`az login`)?")
                        return None
              elif cred_type == 'service_principal':
                   logger.info("Using Azure Service Principal credential.")
                   tenant_id = creds.get('tenant_id')
                   client_id = creds.get('client_id')
                   client_secret = creds.get('client_secret')
                   if not all([tenant_id, client_id, client_secret]):
                        logger.error("Service Principal credentials missing (tenant_id, client_id, or client_secret).")
                        return None
                   try:
                        credential = azure.identity.ClientSecretCredential(
                            tenant_id=tenant_id, client_id=client_id, client_secret=client_secret
                        )
                        credential.get_token("https://management.azure.com/.default") # Test token acquisition
                        logger.info("Azure Service Principal credential obtained successfully.")
                   except Exception as sp_err:
                       logger.error(f"Failed to get token using Service Principal: {sp_err}. Check credentials and permissions.")
                       return None
              elif cred_type == 'managed_identity':
                   msi_client_id = creds.get('msi_client_id')
                   if msi_client_id:
                        logger.info(f"Using User-Assigned Managed Identity (ClientID: {msi_client_id}).")
                        try:
                            credential = azure.identity.ManagedIdentityCredential(client_id=msi_client_id)
                            credential.get_token("https://management.azure.com/.default") # Test
                            logger.info("User-Assigned Managed Identity credential obtained.")
                        except Exception as msi_err:
                            logger.error(f"Failed to get token using User-Assigned MSI (ClientID: {msi_client_id}): {msi_err}.")
                            return None
                   else:
                        logger.info("Using System-Assigned Managed Identity.")
                        try:
                            credential = azure.identity.ManagedIdentityCredential()
                            credential.get_token("https://management.azure.com/.default") # Test
                            logger.info("System-Assigned Managed Identity credential obtained.")
                        except Exception as msi_err:
                            logger.error(f"Failed to get token using System-Assigned MSI: {msi_err}. Is MSI enabled for the environment?")
                            return None
              else:
                   logger.error(f"Unsupported Azure credential type: {cred_type}")
                   return None

              return credential # Return the obtained credential object

         except ImportError: logger.error("Azure identity library not found (`pip install azure-identity`)."); return None
         except azure.identity.CredentialUnavailableError as e:
            logger.error(f"Azure Credential Unavailable: {e}. Check environment or configuration for {cred_type}.")
            return None
         except Exception as e: # Catch other potential errors during credential creation/testing
            logger.error(f"Failed to create or test Azure credential object: {e}", exc_info=True)
            return None

    def _get_gcp_credential(self) -> Optional[Tuple[Any, str]]:
        """Gets GCP credentials object and project ID."""
        creds = self.cloud_credentials
        project_id = creds.get('projrct_id')
        if not project_id:
            logger.error("GCP Project ID is missing for credential creation.")
            return None
        
        try:
            cred_type = creds.get('type')
            credentials = None
            if cred_type == 'application_default':
                logger.info(f"Using GCP Application Default Credentials (ADC) for project {project_id}.")
                try:
                    credentials, discovered_project_id = google.auth.default(scope=["https://www.googleapis.com/auth/cloud-platform"])
                    if not credentials:
                        raise google.auth.exceptions.DefaultCredentialsError("ADC credentials not found.")
                    if discovered_project_id and discovered_project_id != project_id:
                        logger.warning(f"Discovered project ID '{discovered_project_id}' does not match expected '{project_id}'.")  
                    scoped_credentials = credentials.with_quota_project(project_id)
                    logger.info("GCP Project default credentials obtained")
                    return scoped_credentials, project_id
                except google.auth.exceptions.DefaultCredentialsError as e:
                    logger.error(f"GCP Application Default Credentials error: {e}")
                    return None, None
                
            elif cred_type == 'service_account':
                key_file_path = creds.get("key_file")
                if not key_file_path:
                    logger.error("Service Account type selected not 'key_file' path is missing.")
                    return None, None
                logger.info(f"Using GCP Service Account Key file: {key_file_path} for project {project_id}.")
                if not os.path.exists(key_file_path):
                    logger.error(f"GCP Service Account Key file not found at {key_file_path}.")
                    return None, None
                try:
                    credentials = service_account.Credentials.from_service_account_file(
                        key_file_path, scopes=["https://www.googleapis.com/auth/cloud-platform"]
                    )
                    scoped_credentials = credentials.with_quota_project(project_id)
                    logger.info("GCP Service Account credentials obtained")
                    return scoped_credentials, project_id
                except Exception as e:
                    logger.error(f"Failed to create GCP Service Account credentials: {e}")
                    return None, None
            else:
                logger.error(f"Unsupported GCP credential type: {cred_type}"); return None, None
        except(google.auth.exceptions.RefreshError, FileNotFoundError) as e:
            logger.error(f"GCP credential error: {e}")
            return None, None
        except Exception as e:
            logger.error(f"Failed to grt gcp credentials: {e}", exc_info=True)
            return None, None
        
    # Step 4: Set Resource Configuration
    def set_resource_config(self, config: dict) -> bool:
        """ Sets the desired resource configuration directly. """
        logger.info(f"Setting resource configuration...")
        logger.debug(f"Received resource config: {config}")
        res_type = config.get('type')
        create_new = config.get('create_new') 
        if not res_type or create_new is None: 
            logger.error("Resource configuration must include 'type' (string) and 'create_new' (boolean).")
            return False
        
        if self.cloud_provider == 'aws':
            region = config.get('region', self.cloud_credentials.get('region'))
            if not region:
                session = self._get_aws_session()
                region = session.region_name if session else None
            if not region:
                logger.error("AWS region could not be determined. Please provide it in resource config or credentials.")
                return False
            self.resource_configuration['region'] = region
            
            if res_type == 'ec2':
                self.resource_configuration['instance_name'] = config.get('instance_name', f'ai-devops-instance-{uuid.uuid4().hex[:6]}')
                if create_new:
                    self.resource_configuration['instance_type'] = config.get('instance_type', 't2.micro')
            elif res_type == 'ecs':
                self.resource_configuration['cluster_name'] = config.get('cluster_name', f'ai-devops-cluster-{uuid.uuid4().hex[:6]}')
            elif res_type == 'lambda':
                self.resource_configuration['function_name'] = config.get('function_name', f'ai-devops-function-{uuid.uuid4().hex[:6]}')
                if create_new:
                    self.resource_configuration['memory'] = config.get('memory', 128)
        
        elif self.cloud_provider == 'azure':
             # Location and Resource Group are essential
            location = config.get('location', self.cloud_credentials.get('location')) 
            rg = config.get('resource_group')
            if not location or not rg:
                logger.error("Azure 'location' and 'resource_group' must be provided in resource config.")
                return False
            self.resource_configuration['location'] = location
            self.resource_configuration['resource_group'] = rg
             # Add specific Azure resource fields
            if res_type == 'vm':
                self.resource_configuration['vm_name'] = config.get('vm_name', f'aidevops-vm-{uuid.uuid4().hex[:6]}')
                if create_new:
                    self.resource_configuration['vm_size'] = config.get('vm_size', 'Standard_B1s')
                    self.resource_configuration['admin_username'] = config.get('admin_username', 'azureuser')
            elif res_type == 'app_service':
                self.resource_configuration['app_name'] = config.get('app_name', f'aidevops-app-{uuid.uuid4().hex[:6]}')
                
        elif self.cloud_provider == 'gcp':
             # Project ID is essential (should be in creds)
            project_id = config.get('project_id', self.cloud_credentials.get('project_id'))
            if not project_id:
                logger.error("GCP 'project_id' could not be determined.")
                return False
            self.resource_configuration['project_id'] = project_id
            # Zone or Region often needed
            zone = config.get('zone')
            region = config.get('region')
            if not zone and res_type == 'vm': # Zone needed for VM
                logger.error("GCP 'zone' must be provided for VM resource config.")
                return False
            if not region and res_type == 'cloud_run': # Region needed for Cloud Run
                logger.error("GCP 'region' must be provided for Cloud Run resource config.")
                return False
            if zone: self.resource_configuration['zone'] = zone
            if region: self.resource_configuration['region'] = region

            # Add specific GCP resource fields
            if res_type == 'vm':
                self.resource_configuration['instance_name'] = config.get('instance_name', f'ai-devops-instance-{uuid.uuid4().hex[:6]}')
                if create_new:
                    self.resource_configuration['machine_type'] = config.get('machine_type', 'e2-micro')
            elif res_type == 'cloud_run':
                self.resource_configuration['service_name'] = config.get('service_name', f'ai-devops-service-{uuid.uuid4().hex[:6]}')
    
        # Handle details for existing resources
        if not create_new:
            if config.get('selected_details'):
                self.selected_resource_details = config['selected_details']
                logger.info(f"Using provided details for existing resource: {self.selected_resource_details.get('name', 'N/A')}")
            else:
                # Try to synthesize basic info from config if details missing
                res_type_display = f"{self.cloud_provider.upper()} {res_type.upper()} (Existing)"
                # Map common config keys to a 'name' attribute
                name_key = {
                    'ec2': 'instance_name', 'vm': 'vm_name', 'ecs': 'cluster_name',
                    'lambda': 'function_name', 'app_service': 'app_name', 'cloud_run': 'service_name'
                }.get(res_type, 'name') # Default key is 'name' if not found
                res_name = self.resource_configuration.get(name_key, 'Name Not Provided in Config')
                self.selected_resource_details = {'type': res_type_display, 'name': res_name}
                logger.warning(f"Using existing resource '{res_name}', but full 'selected_details' not provided. Instructions might be limited.")
            # Clear generated key paths if using existing VM-like resource, as script didn't create its key
            if res_type in ['ec2', 'vm']:
                self.ssh_key_paths = {}
                logger.info("Cleared generated SSH key paths as an existing VM-like resource was selected.")

        logger.info("Resource configuration set successfully.")
        logger.debug(f"Final resource configuration state: {self.resource_configuration}")
        return True
    
    def _create_aws_ec2_instance(self, ec2_client) -> bool:
        logger.info("Executing creation of NEW AWS EC2 instance...")
        instance_type = self.resource_configuration.get('instance_type', 't2.micro')
        # Use instance name from config, fallback to default if needed
        instance_name_tag = self.resource_configuration.get('instance_name', f'ai-devops-instance-{uuid.uuid4().hex[:6]}')
        key_name_base = f"ai-devops-{instance_name_tag}-key" # Include instance name in key base
        key_filename_base = key_name_base  # Define key_filename_base based on key_name_base
        sg_name = f"ai-devops-{instance_name_tag}-sg" # Include instance name in sg base
        region = self.resource_configuration.get('region')
        if not region: logger.error("AWS Region missing in configuration."); return False

        key_temp_dir = None
        
        try:
            private_key_path, public_key_material, _, temp_key_dir = generate_ssh_key_pair(key_name_base)
            if not private_key_path or not public_key_material or not temp_key_dir:
                logger.error("Failed ot generate SSH key pair.")
                return False
            
            self.ssh_key_paths = {
                'private': private_key_path,
                'public': os.path.join(temp_key_dir, f"{key_filename_base}.pub"),
                'key_name': None,
                'temp_dir': temp_key_dir
            }
            logger.debug(F"SSH key paths stored: {self.ssh_key_paths}")
            
            key_pair_name_aws = None
            try:
                ec2_client.describe_key_pairs(KeyNames=[key_name_base])
                key_pair_name_aws = key_name_base
                logger.info(f"Using existing AWS key pair found with name: {key_name_base}")
                self.ssh_key_paths['key_name'] = key_pair_name_aws
                self.ssh_key_paths['private'] = f"~/.ssh/{key_pair_name_aws}.pem (Assumed Location - Use Existing Key)" # Indicate existing key needed
                self.ssh_key_paths['public'] = "N/A (Managed by AWS)"
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidKeyPair.NotFound':
                    logger.info(f"Importing local public key to AWS EC2 as '{key_name_base}'...")
                    try:
                        key_pair = ec2_client.import_key_pair(KeyName=key_name_base, PublicKeyMaterial=public_key_material.encode('utf-8'))
                        key_pair_name_aws = key_pair['KeyName']
                        self.ssh_key_paths['key_name'] = key_pair_name_aws # Store the confirmed name
                        logger.info(f"Successfully imported key pair to AWS: {key_pair_name_aws}")
                    except ClientError as import_e:
                        logger.error(f"Failed to import generated key pair to AWS: {import_e}")
                        if temp_key_dir: 
                            shutil.rmtree(temp_key_dir, onerror=remove_readonly)
                        self.ssh_key_paths = {}
                        return False 
                else:
                    logger.error(f"Error checking for existing AWS key pair: {e}")
                    raise
                
            if not key_pair_name_aws:
                logger.error("Failed to obtain an AWS key pair name for launching the instance.")
                if temp_key_dir and 'key_name' not in self.ssh_key_paths : # Only cleanup if we didn't decide to use an existing AWS key
                    shutil.rmtree(temp_key_dir, onerror=remove_readonly)
                    self.ssh_key_paths = {}
                return False
            
            sg_id = None
            try:
                # Check if SG already exists
                response = ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [sg_name]}])
                if response.get('SecurityGroups'):
                    sg_id = response['SecurityGroups'][0]['GroupId']
                    logger.info(f"Using existing Security Group: {sg_name} ({sg_id})")
                else:
                    logger.info(f"Creating new Security Group: {sg_name}")
                    # Find default VPC
                    vpc_response = ec2_client.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
                    if not vpc_response or not vpc_response.get('Vpcs'):
                        # If no default VPC, try to find *any* VPC
                        vpc_response = ec2_client.describe_vpcs()
                        if not vpc_response or not vpc_response.get('Vpcs'):
                            logger.error("No VPCs found in the account/region. Cannot create Security Group.")
                            return False
                        vpc_id = vpc_response['Vpcs'][0]['VpcId']
                        logger.warning(f"No default VPC found. Using first available VPC: {vpc_id}")
                    else:
                        vpc_id = vpc_response['Vpcs'][0]['VpcId']
                        logger.info(f"Using default VPC: {vpc_id}")
                        
                    sg = ec2_client.create_security_group(GroupName=sg_name, Description=f'AI DevOps SG for {instance_name_tag}', VpcId=vpc_id)
                    sg_id = sg['GroupId']
                    # Add ingress rules (SSH, HTTP, HTTPS)
                    ec2_client.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[
                        {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Allow SSH from anywhere'}]},
                        {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Allow HTTP from anywhere'}]},
                        {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Allow HTTPS from anywhere'}]}
                    ])
                    logger.info(f"Created Security Group {sg_id} and allowed SSH/HTTP/HTTPS ingress from 0.0.0.0/0.")
            except ClientError as e:
                logger.error(f"Error describing or creating Security Group '{sg_name}': {e}")
                return False
                
            if not sg_id: logger.error("Failed to get Security Group ID."); return False

             # --- AMI Selection (Ubuntu 22.04 LTS preferred, Amazon Linux 2 fallback) ---
            ami_id = None
            default_ssh_user = None
            try:
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

                if images and images.get('Images'):
                    # Sort by creation date to get the latest one
                    ami_id = sorted(images['Images'], key=lambda x: x.get('CreationDate', ''), reverse=True)[0]['ImageId']
                    default_ssh_user = 'ubuntu' # Default user for Ubuntu AMIs
                    logger.info(f"Using Ubuntu 22.04 LTS AMI: {ami_id}")
                else:
                    logger.warning("Could not find Ubuntu 22.04 LTS AMI. Falling back to Amazon Linux 2 AMI search...")
                    amzn_filters = [
                        {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                        {'Name': 'state', 'Values': ['available']},
                        {'Name': 'architecture', 'Values': ['x86_64']},
                        {'Name': 'virtualization-type', 'Values': ['hvm']}
                    ]
                    images = ec2_client.describe_images(Owners=['amazon'], Filters=amzn_filters)
                    if not images or not images.get('Images'):
                        logger.error("Could not find Amazon Linux 2 AMI either. Cannot launch instance.")
                        return False
                    ami_id = sorted(images['Images'], key=lambda x: x.get('CreationDate', ''), reverse=True)[0]['ImageId']
                    default_ssh_user = 'ec2-user' # Default for Amazon Linux
                    logger.info(f"Using fallback Amazon Linux 2 AMI: {ami_id}")

            except ClientError as e:
                logger.error(f"Error finding AMI: {e}")
                return False
            
            if not ami_id or not default_ssh_user:
                logger.error("Failed to determine a suitable AMI ID or default SSH user.")
                return False

            logger.info(f"Requesting instance launch: Name='{instance_name_tag}', Type='{instance_type}', AMI='{ami_id}', Key='{key_pair_name_aws}', SG='{sg_id}'")
            try:
                run_response = ec2_client.run_instances(
                    ImageId=ami_id, InstanceType=instance_type, KeyName=key_pair_name_aws, SecurityGroupIds=[sg_id], MinCount=1, MaxCount=1,
                    TagSpecifications=[{'ResourceType': 'instance','Tags': [{'Key': 'Name', 'Value': instance_name_tag},{'Key':'CreatedBy','Value':'ai-devops-tool'}]}]
                )
                instance_id = run_response['Instances'][0]['InstanceId']
                logger.info(f"Instance requested: {instance_id}. Waiting for 'running' state...")

                # Wait for the instance to be running
                waiter = ec2_client.get_waiter('instance_running');
                waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 40}) # Wait up to 10 mins
                logger.info(f"Instance {instance_id} is now running.")

                # Describe the instance again to get Public IP
                desc_response = ec2_client.describe_instances(InstanceIds=[instance_id])
                if not desc_response or not desc_response.get('Reservations') or not desc_response['Reservations'][0].get('Instances'):
                    logger.error("Failed to describe instance after launch.")
                    # Attempt to terminate the potentially orphaned instance? Risky. Log and return False.
                    return False

                instance_info = desc_response['Reservations'][0]['Instances'][0]
                public_ip = instance_info.get('PublicIpAddress')
                public_dns = instance_info.get('PublicDnsName')
                
                self.created_resource_details = {
                    'type': 'AWS EC2 Instance',
                    'id': instance_id,
                    'name': instance_name_tag, # Include the name used
                    'region': region,
                    'instance_type': instance_type,
                    'ami_id': ami_id,
                    'key_pair_name': key_pair_name_aws,
                    'security_group_id': sg_id,
                    'security_group_name': sg_name,
                    'public_ip': public_ip,
                    'public_dns': public_dns,
                    'ssh_user': default_ssh_user,
                    'ssh_key_private_path': self.ssh_key_paths.get('private', 'N/A - Check AWS Key Pair')
                }
                
                logger.info(f"EC2 Instance Created Successfully:")
                logger.info(f"  ID: {instance_id}")
                logger.info(f"  Name: {instance_name_tag}")
                logger.info(f"  IP: {public_ip}")
                logger.info(f"  DNS: {public_dns}")
                logger.info(f"  User: {default_ssh_user}")
                logger.info(f"  Key Pair: {key_pair_name_aws}")
                logger.info(f"  Key File Instruction: Use key corresponding to '{key_pair_name_aws}'. Path hint: {self.created_resource_details['ssh_key_private_path']}")

                return True
            
            except ClientError as e:
                logger.error(f"AWS API error launching or waiting for EC2 instance: {e}");
                # Attempt cleanup? If instance was requested, maybe try terminate? Risky.
                return False
            except Exception as e: # Catch waiter errors (botocore.exceptions.WaiterError) too
                logger.error(f"Error launching instance or waiting for it to run: {e}", exc_info=True);
                return False

        except Exception as e: # Catch errors in key gen or SG setup phase
            logger.error(f"Unexpected error during EC2 instance setup: {e}", exc_info=True)
            # Ensure cleanup of generated keys if error occurred before launch attempt
            if key_temp_dir and os.path.exists(key_temp_dir):
                try: shutil.rmtree(key_temp_dir, onerror=remove_readonly)
                except Exception as cleanup_e: logger.error(f"Error cleaning up key dir during exception handling: {cleanup_e}")
            self.ssh_key_paths = {} # Clear paths on failure
            return False
        
    def _create_aws_ecs_cluster(self, ecs_client) -> bool:
        logger.info("Executing creation of NEW ECS cluster...")
        cluster_name = self.resource_configuration.get('cluster_name')
        region = self.resource_configuration.get('region')
        if not cluster_name: logger.error("ECS Cluster name missing in configuration."); return False
        if not region: logger.error("AWS Region missing in configuration."); return False

        try:
            logger.info(f"Attempting to create ECS Cluster '{cluster_name}' in region {region}...")
            response = ecs_client.create_cluster(clusterName=cluster_name)
            cluster_arn = response['cluster']['clusterArn']
            status = response['cluster']['status']
            self.created_resource_details = {
                'type': 'AWS ECS Cluster',
                'name': cluster_name,
                'arn': cluster_arn,
                'status': status,
                'region': region
        }
            logger.info(f"ECS Cluster created: ARN={cluster_arn}, Status={status}")
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            # Handle common case where cluster already exists
            if error_code == 'ResourceInUseException' or (error_code == 'InvalidParameterException' and 'already exists' in str(e)):
                logger.warning(f"ECS Cluster '{cluster_name}' already exists. Attempting to retrieve its details.")
                try:
                    # Describe the existing cluster
                    desc_response = ecs_client.describe_clusters(clusters=[cluster_name])
                    if desc_response.get('clusters'):
                        existing_cluster = desc_response['clusters'][0]
                        self.selected_resource_details = { # Store as selected, not created
                            'type': 'AWS ECS Cluster (Existing)',
                            'name': existing_cluster['clusterName'],
                            'arn': existing_cluster['clusterArn'],
                            'status': existing_cluster['status'],
                            'region': region
                        }
                        # Clear created details as we used existing
                        self.created_resource_details = {}
                        # Update configuration to reflect existing resource
                        self.resource_configuration['create_new'] = False
                        self.resource_configuration['cluster_arn'] = existing_cluster['clusterArn'] # Store ARN in config too
                        logger.info(f"Using existing ECS cluster: ARN={existing_cluster['clusterArn']}, Status={existing_cluster['status']}")
                        return True # Success, as the desired state (cluster exists) is met
                    else:
                        logger.error(f"Cluster '{cluster_name}' reported as existing, but could not describe it.")
                        return False
                except ClientError as desc_e:
                    logger.error(f"Failed to describe existing cluster '{cluster_name}' after creation conflict: {desc_e}")
                    return False
            else:
                logger.error(f"AWS API error creating ECS cluster: {e}"); return False
        except Exception as e:
             logger.error(f"Unexpected error creating ECS cluster: {e}", exc_info=True); return False
             
    def _create_aws_lambda_function(self, lambda_client, iam_client) -> bool:
        logger.info("Executing creation of NEW Lambda function...")
        function_name = self.resource_configuration.get('function_name')
        memory = self.resource_configuration.get('memory', 128)
        region = self.resource_configuration.get('region')
        if not function_name: logger.error("Lambda function name missing."); return False
        if not region: logger.error("AWS Region missing."); return False

        # Determine runtime based on detected stack
        runtime = None
        if self.detected_stack == 'python': runtime = 'python3.11' # Use a recent Python runtime
        elif self.detected_stack == 'nodejs': runtime = 'nodejs20.x' # Use a recent Node runtime
        elif self.detected_stack == 'java': runtime = 'java17' # Use a recent Java runtime
        elif self.detected_stack == 'golang': runtime = 'go1.x'
        elif self.detected_stack == 'dotnet': runtime = 'dotnet6' # Or dotnet8 if available/needed
        elif self.detected_stack == 'ruby': runtime = 'ruby3.2'
        # Add other runtimes as needed (rust, custom, etc.)
        else:
            logger.warning(f"Unsupported or unknown stack '{self.detected_stack}' for Lambda runtime. Defaulting to python3.11.")
            runtime = 'python3.11'

        # Basic handler name based on runtime (can be overridden in config if needed)
        default_handler = {
             'python3.11': 'lambda_function.lambda_handler',
             'nodejs20.x': 'index.handler',
             'java17': 'com.example.Handler::handleRequest', # Example Java handler
             'go1.x': 'main', # Go usually compiles to 'main' or 'bootstrap'
             'dotnet6': 'Function::Function.FunctionHandler', # Example .NET handler
             'ruby3.2': 'lambda_function.lambda_handler'
        }.get(runtime, 'index.handler') # Fallback handler

        handler_name = self.resource_configuration.get('handler', default_handler)
        role_name = f"{function_name}-execution-role"
        temp_files_to_clean = []
        
        try:
             # --- IAM Role ---
            role_arn = None
            try:
                # Check if role exists
                role_response = iam_client.get_role(RoleName=role_name)
                role_arn = role_response['Role']['Arn']
                logger.info(f"Using existing IAM execution role: {role_name} ({role_arn})")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    logger.info(f"Creating new IAM execution role: {role_name}")
                    assume_role_policy = json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    })
                    try:
                        role_response = iam_client.create_role(
                            RoleName=role_name,
                            AssumeRolePolicyDocument=assume_role_policy,
                            Description=f"Execution role for {function_name} Lambda created by AI DevOps tool"
                        )
                        role_arn = role_response['Role']['Arn']
                        logger.info(f"Created role {role_name}. Attaching basic execution policy...")
                        # Attach AWSLambdaBasicExecutionRole policy
                        policy_arn = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
                        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                        logger.info(f"Attached policy {policy_arn}. Waiting for IAM propagation...")
                        time.sleep(15) # IAM changes can take time to propagate
                    except ClientError as create_err:
                        logger.error(f"Failed to create or attach policy to IAM role {role_name}: {create_err}")
                        return False
                else:
                    logger.error(f"Error checking/creating IAM role {role_name}: {e}")
                    raise # Re-raise unexpected errors

            if not role_arn: logger.error("Failed to get or create IAM role ARN."); return False

            # --- Dummy Code Package ---
            # Create a minimal valid code package for the specified runtime
            dummy_content, dummy_filename = "", ""
            if runtime.startswith('python'):
                dummy_filename = "lambda_function.py"
                dummy_content = "import json\n\ndef lambda_handler(event, context):\n    print('Hello from AI DevOps Lambda!')\n    return {'statusCode': 200, 'body': json.dumps('Success!')}\n"
            elif runtime.startswith('nodejs'):
                dummy_filename = "index.js"
                dummy_content = "exports.handler = async (event) => {\n    console.log('Hello from AI DevOps Lambda!');\n    const response = { statusCode: 200, body: JSON.stringify('Success!') };\n    return response;\n};"
            elif runtime.startswith('java'):
                # Java requires a compiled JAR/ZIP. Creating a dummy source is complex.
                # For now, we'll skip the dummy code creation for Java. The create_function call will likely fail
                # without a valid Code.S3Bucket/S3Key or ZipFile. This needs enhancement.
                logger.error("Dummy code generation for Java runtime is not implemented. Cannot create function without pre-existing code package.")
                # TODO: Implement dummy JAR creation or require S3 location for Java
                return False
            elif runtime.startswith('go'):
                dummy_filename = "main.go" # Go handler name defaults to executable name
                handler_name = "main" # Often compiled executable name
                dummy_content = "package main\n\nimport (\n\t\"fmt\"\n\t\"github.com/aws/aws-lambda-go/lambda\"\n)\n\ntype MyEvent struct {\n\tName string `json:\"name\"`\n}\n\nfunc HandleRequest(event MyEvent) (string, error) {\n\tfmt.Println(\"Hello from AI DevOps Lambda!\")\n\treturn fmt.Sprintf(\"Success, %s!\", event.Name), nil\n}\n\nfunc main() {\n\tlambda.Start(HandleRequest)\n}\n"
                # Go needs compilation. We cannot create a zip directly here easily.
                logger.error("Dummy code generation for Go runtime requires compilation. Cannot create function without pre-existing code package.")
                # TODO: Implement dummy Go build/zip or require S3 location
                return False
            # Add cases for other runtimes as needed
            else:
                logger.error(f"Dummy code generation for runtime '{runtime}' is not implemented.")
                return False

            temp_code_dir = tempfile.mkdtemp(prefix="ai-devops-lambda-code-")
            temp_files_to_clean.append(temp_code_dir) # Add dir for cleanup
            zip_path = os.path.join(temp_code_dir, f"{function_name}_dummy.zip")
            dummy_file_path = os.path.join(temp_code_dir, dummy_filename)

            try:
                with open(dummy_file_path, 'w') as f: f.write(dummy_content)
                import zipfile
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                    zf.write(dummy_file_path, arcname=dummy_filename) # Write file into zip root
                logger.info(f"Created dummy code package at: {zip_path}")
                with open(zip_path, 'rb') as f: zip_content_bytes = f.read()
            except Exception as zip_e:
                logger.error(f"Failed to create dummy code zip package: {zip_e}")
                return False # Cleanup will happen in finally block

            # --- Create Lambda Function ---
            logger.info(f"Creating Lambda function '{function_name}' (Runtime: {runtime}, Handler: {handler_name}, Memory: {memory}MB)...")
            try:
                create_response = lambda_client.create_function(
                    FunctionName=function_name,
                    Runtime=runtime,
                    Role=role_arn,
                    Handler=handler_name,
                    Code={'ZipFile': zip_content_bytes},
                    MemorySize=memory,
                    Timeout=30, # Reasonable default timeout
                    Publish=True, # Publish a version immediately
                    Tags={'CreatedBy': 'ai-devops-tool'}
                )
                function_arn = create_response['FunctionArn']
                function_version = create_response.get('Version', '1') # Get published version
                logger.info(f"Lambda function created: ARN={function_arn}, Version={function_version}")

                self.created_resource_details = {
                    'type': 'AWS Lambda Function',
                    'name': function_name,
                    'arn': function_arn,
                    'version': function_version,
                    'runtime': runtime,
                    'memory': memory,
                    'timeout': 30,
                    'handler': handler_name,
                    'role_arn': role_arn,
                    'region': region
                }
                return True

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceConflictException':
                    logger.warning(f"Lambda function '{function_name}' already exists. Attempting to retrieve details.")
                    try:
                        func_data = lambda_client.get_function(FunctionName=function_name)['Configuration']
                        self.selected_resource_details = { # Store as selected
                            'type': 'AWS Lambda Function (Existing)',
                            'name': func_data['FunctionName'],
                            'arn': func_data['FunctionArn'],
                            'version': func_data.get('Version', 'LATEST'),
                            'runtime': func_data['Runtime'],
                            'memory': func_data['MemorySize'],
                            'timeout': func_data['Timeout'],
                            'handler': func_data['Handler'],
                            'role_arn': func_data['Role'],
                            'region': region
                        }
                        self.created_resource_details = {} # Clear created details
                        self.resource_configuration['create_new'] = False # Update config
                        logger.info(f"Using existing Lambda function: ARN={func_data['FunctionArn']}")
                        return True # Success, desired state met
                    except ClientError as get_e:
                        logger.error(f"Function '{function_name}' reported as existing, but failed to retrieve details: {get_e}")
                        return False
                elif error_code == 'InvalidParameterValueException':
                    logger.error(f"Invalid parameter creating Lambda function: {e}. Check role propagation, runtime, handler, or code package.")
                    return False
                else:
                    logger.error(f"AWS API error creating Lambda function: {e}"); return False

        except Exception as e:
             logger.error(f"Unexpected error creating Lambda function: {e}", exc_info=True); return False
        finally:
            # --- Cleanup Temporary Code Files ---
            for path in temp_files_to_clean:
                if os.path.isdir(path):
                    try: shutil.rmtree(path, onerror=remove_readonly); logger.debug(f"Cleaned up temp dir: {path}")
                    except Exception as clean_e: logger.warning(f"Could not cleanup temp code directory {path}: {clean_e}")
                elif os.path.isfile(path):
                    try: os.remove(path); logger.debug(f"Cleaned up temp file: {path}")
                    except Exception as clean_e: logger.warning(f"Could not cleanup temp code file {path}: {clean_e}")

    def _create_azure_vm(self, compute_client, network_client, resource_client) -> bool:
        logger.info("Executing creation of NEW Azure VM...")
        rg_name = self.resource_configuration.get('resource_group')
        location = self.resource_configuration.get('location')
        vm_name = self.resource_configuration.get('vm_name')
        vm_size = self.resource_configuration.get('vm_size')
        admin_username = self.resource_configuration.get('admin_username')

        # Validate required parameters
        if not all([rg_name, location, vm_name, vm_size, admin_username]):
             logger.error("Missing required Azure VM configuration parameters: resource_group, location, vm_name, vm_size, admin_username."); return False

        # Ensure resource group exists (create if not) - Best practice
        try:
            logger.info(f"Ensuring Resource Group '{rg_name}' exists in {location}...")
            resource_client.resource_groups.create_or_update(rg_name, {'location': location})
            logger.info(f"Resource Group '{rg_name}' ensured.")
        except Exception as rg_e:
            logger.error(f"Failed to create or update Resource Group '{rg_name}': {rg_e}"); return False

        key_name_base = f"ai-devops-{vm_name}-key"
        key_temp_dir = None

        try:
            # --- SSH Key Generation ---
            private_key_path, public_key_content, _, temp_key_dir = generate_ssh_key_pair(key_name_base)
            if not private_key_path or not public_key_content or not temp_key_dir:
                logger.error("Failed to generate SSH key pair for Azure VM."); return False
            key_temp_dir = temp_key_dir # Track for cleanup
            key_filename_base = key_name_base  # Define key_filename_base based on key_name_base
            self.ssh_key_paths = { # Store generated key details
                'private': private_key_path,
                'public': os.path.join(temp_key_dir, f"{key_filename_base}.pub"),
                'key_name': key_name_base, # Use base name as reference
                'temp_dir': temp_key_dir
            }
            logger.debug(f"SSH key generated for Azure VM: {self.ssh_key_paths}")

            # --- Network Resources (VNet, Subnet, PIP, NIC, NSG) ---
            vnet_name = f"{vm_name}-vnet"
            subnet_name = "default"
            public_ip_name = f"{vm_name}-pip"
            nic_name = f"{vm_name}-nic"
            nsg_name = f"{vm_name}-nsg"
            logger.info("Ensuring Azure network resources (VNet, Subnet, Public IP, NSG, NIC)...")

            try:
                # VNet
                logger.debug(f"Checking/Creating VNet: {vnet_name}")
                vnet_poller = network_client.virtual_networks.begin_create_or_update(rg_name,vnet_name,{"location":location,"address_space":{"address_prefixes":["10.0.0.0/16"]}})
                vnet_result = vnet_poller.result()
                logger.debug(f"VNet '{vnet_name}' ensured.")

                # Subnet
                logger.debug(f"Checking/Creating Subnet: {subnet_name} in {vnet_name}")
                subnet_poller = network_client.subnets.begin_create_or_update(rg_name,vnet_name,subnet_name,{"address_prefix":"10.0.0.0/24"})
                subnet_result = subnet_poller.result()
                logger.debug(f"Subnet '{subnet_name}' ensured.")

                # Public IP
                logger.debug(f"Checking/Creating Public IP: {public_ip_name}")
                pip_poller = network_client.public_ip_addresses.begin_create_or_update(rg_name,public_ip_name,{"location":location,"sku":{"name":"Standard"},"public_ip_allocation_method":"Static", "tags": {"CreatedBy": "ai-devops-tool"}})
                pip_result = pip_poller.result()
                logger.debug(f"Public IP '{public_ip_name}' ensured. IP: {pip_result.ip_address}")

                # Network Security Group (NSG)
                logger.debug(f"Checking/Creating NSG: {nsg_name}")
                nsg_poller = network_client.network_security_groups.begin_create_or_update(
                    rg_name, nsg_name, {"location": location, "tags": {"CreatedBy": "ai-devops-tool"}}
                )
                nsg_result = nsg_poller.result()
                logger.debug(f"NSG '{nsg_name}' ensured.")

                # NSG Rule for SSH (Port 22)
                ssh_rule_name = "AllowSSH"
                logger.debug(f"Checking/Creating NSG Rule: {ssh_rule_name} in {nsg_name}")
                rule_poller = network_client.security_rules.begin_create_or_update(
                    rg_name, nsg_name, ssh_rule_name, {
                        "protocol": "Tcp",
                        "source_address_prefix": "*", # Be careful in production, restrict this
                        "destination_address_prefix": "*",
                        "access": "Allow",
                        "direction": "Inbound",
                        "source_port_range": "*",
                        "destination_port_range": "22",
                        "priority": 100 # Lower number = higher priority
                    }
                )
                rule_poller.result()
                logger.debug(f"NSG Rule '{ssh_rule_name}' ensured.")
                # Add rules for HTTP/HTTPS if needed here

                # Network Interface (NIC)
                logger.debug(f"Checking/Creating NIC: {nic_name}")
                nic_poller = network_client.network_interfaces.begin_create_or_update(rg_name,nic_name,{
                    "location":location,
                    "ip_configurations":[{
                        "name":"ipconfig1",
                        "subnet":{"id": subnet_result.id},
                        "public_ip_address":{"id": pip_result.id}
                    }],
                    "network_security_group": {"id": nsg_result.id}, # Associate NSG
                    "tags": {"CreatedBy": "ai-devops-tool"}
                })
                nic_result = nic_poller.result()
                logger.info("Azure network resources ready.")

            except azure.core.exceptions.HttpResponseError as net_e:
                logger.error(f"Azure API error creating network resources: {net_e.message}"); return False
            except Exception as net_e:
                logger.error(f"Unexpected error creating Azure network resources: {net_e}", exc_info=True); return False


            # --- VM Configuration ---
            # Use a common Ubuntu LTS image
            image_reference = {"publisher":"Canonical","offer":"0001-com-ubuntu-server-jammy","sku":"22_04-lts-gen2","version":"latest"}
            logger.info(f"Using VM Image: {image_reference['publisher']}/{image_reference['offer']}/{image_reference['sku']}/{image_reference['version']}")

            vm_parameters = {
                "location": location,
                "tags": {"CreatedBy": "ai-devops-tool"},
                "properties": {
                    "hardwareProfile": {"vmSize": vm_size},
                    "storageProfile": {
                        "imageReference": image_reference,
                        "osDisk": {
                            "createOption":"FromImage",
                            "managedDisk":{"storageAccountType":"Standard_LRS"} # Standard HDD, use StandardSSD_LRS or Premium_LRS for better performance
                        }
                    },
                    "osProfile": {
                        "computerName": vm_name, # Hostname inside the VM
                        "adminUsername": admin_username,
                        "linuxConfiguration":{
                            "disablePasswordAuthentication": True,
                            "ssh":{
                                "publicKeys":[{
                                    "path":f"/home/{admin_username}/.ssh/authorized_keys",
                                    "keyData": public_key_content
                                }]
                            }
                        }
                    },
                    "networkProfile": {
                        "networkInterfaces": [{"id": nic_result.id}] # Reference the created NIC
                    }
                }
            }

            # --- Create VM ---
            logger.info(f"Creating Azure VM '{vm_name}' (Size: {vm_size}). This may take a few minutes...")
            try:
                vm_poller = compute_client.virtual_machines.begin_create_or_update(rg_name, vm_name, vm_parameters)
                vm_result = vm_poller.result() # Wait for completion
                logger.info(f"VM '{vm_name}' creation polling finished. Status: {vm_poller.status()}")

                if vm_poller.status().lower() != 'succeeded':
                    logger.error(f"Azure VM creation polling finished with status: {vm_poller.status()}. Check Azure portal for details.")
                    # Attempt to get error details if available
                    # final_poller_state = vm_poller.polling_method()._initial_response.context['azure_async_operation'] # Example, might change
                    # logger.error(f"Polling state: {final_poller_state}")
                    return False

                # Get updated IP address after creation (it might not be available on the first PIP result)
                final_pip_details = network_client.public_ip_addresses.get(rg_name, public_ip_name)
                public_ip_address = final_pip_details.ip_address if final_pip_details else "N/A"

                self.created_resource_details = {
                    'type': 'Azure VM',
                    'name': vm_result.name,
                    'id': vm_result.id,
                    'resource_group': rg_name,
                    'location': location,
                    'size': vm_size,
                    'public_ip': public_ip_address,
                    'admin_username': admin_username,
                    # Provide the path to the *generated* private key
                    'ssh_key_private_path': self.ssh_key_paths.get('private')
                }
                logger.info(f"Azure VM Created Successfully:")
                logger.info(f"  Name: {vm_result.name}")
                logger.info(f"  ID: {vm_result.id}")
                logger.info(f"  IP: {public_ip_address}")
                logger.info(f"  User: {admin_username}")
                logger.info(f"  Key File Instruction: Use the generated key at '{self.created_resource_details['ssh_key_private_path']}'")

                return True

            except azure.core.exceptions.HttpResponseError as vm_e:
                logger.error(f"Azure API error creating VM: {vm_e.message}"); return False
            except Exception as vm_e:
                logger.error(f"Unexpected error creating Azure VM: {vm_e}", exc_info=True); return False

        except Exception as e: # Catch errors in key gen or initial RG check phase
            logger.error(f"Unexpected error during Azure VM setup: {e}", exc_info=True)
            return False
        finally:
             # Cleanup generated SSH key temp dir
            if key_temp_dir and os.path.exists(key_temp_dir):
                try: shutil.rmtree(key_temp_dir, onerror=remove_readonly)
                except Exception as cleanup_e: logger.warning(f"Could not cleanup temp key directory {key_temp_dir}: {cleanup_e}")
             # Clear paths even if cleanup failed directory removal
            self.ssh_key_paths = {}

    def _create_gcp_vm(self, compute_client: compute_v1.InstancesClient, credentials, project_id: str) -> bool:
        logger.info("Executing creation of NEW GCP VM...")
        instance_name = self.resource_configuration.get('instance_name')
        zone = self.resource_configuration.get('zone')
        machine_type = self.resource_configuration.get('machine_type')

        if not all([instance_name, zone, machine_type]):
            logger.error("Missing required GCP VM configuration parameters: instance_name, zone, machine_type."); return False

        key_name_base = f"ai-devops-{instance_name}-key"
        key_filename_base = key_name_base  # Define key_filename_base based on key_name_base
        ssh_user = "gcpuser" # Common convention, can be customized
        key_temp_dir = None

        try:
            # --- SSH Key Generation ---
            private_key_path, public_key_content, _, temp_key_dir = generate_ssh_key_pair(key_name_base)
            if not private_key_path or not public_key_content or not temp_key_dir:
                logger.error("Failed to generate SSH key pair for GCP VM."); return False
            key_temp_dir = temp_key_dir # Track for cleanup
            self.ssh_key_paths = { # Store generated key details
                'private': private_key_path,
                'public': os.path.join(temp_key_dir, f"{key_filename_base}.pub"),
                'key_name': key_name_base, # Use base name as reference
                'temp_dir': temp_key_dir
            }
            # Format for GCP metadata: username:key_content
            ssh_key_metadata_value = f"{ssh_user}:{public_key_content}"
            logger.debug(f"SSH key generated for GCP VM: {self.ssh_key_paths}")

            # --- Image Selection ---
            # Use a recent Debian image (common default)
            image_project = "debian-cloud"
            image_family = "debian-11" # Or debian-12 if preferred/available
            try:
                image_client = compute_v1.ImagesClient(credentials=credentials)
                latest_image = image_client.get_from_family(project=image_project, family=image_family)
                source_disk_image = latest_image.self_link
                logger.info(f"Using GCP Image: {source_disk_image}")
            except Exception as img_e:
                logger.error(f"Failed to get GCP image {image_family} from {image_project}: {img_e}")
                return False

            # --- Machine Type URL ---
            machine_type_url = f"projects/{project_id}/zones/{zone}/machineTypes/{machine_type}"

            # --- Instance Configuration ---
            instance_config = compute_v1.Instance(
                name=instance_name,
                machine_type=machine_type_url,
                # Network: Use default network, request external IP
                network_interfaces=[compute_v1.NetworkInterface(
                    name="global/networks/default", # Use default network
                    access_configs=[compute_v1.AccessConfig(
                        name="External NAT",
                        type_="ONE_TO_ONE_NAT" # Request External IP
                    )]
                )],
                # Disk: Create a boot disk from the selected image
                disks=[compute_v1.AttachedDisk(
                    initialize_params=compute_v1.AttachedDiskInitializeParams(
                        source_image=source_disk_image,
                        disk_size_gb=10 # Small default boot disk
                    ),
                    auto_delete=True, # Delete disk when VM is deleted
                    boot=True
                )],
                # Metadata: Add the generated SSH key
                metadata=compute_v1.Metadata(items=[
                    compute_v1.Items(key="ssh-keys", value=ssh_key_metadata_value),
                    compute_v1.Items(key="created-by", value="ai-devops-tool") # Add custom metadata
                ]),
                # Tags: Allow firewall rules to target this instance
                tags=compute_v1.Tags(items=["ai-devops-instance", "http-server", "https-server"]) # Common tags
            )

            # --- Insert Instance ---
            logger.info(f"Creating GCP instance '{instance_name}' in zone '{zone}'. This may take a few minutes...")
            try:
                operation = compute_client.insert(project=project_id, zone=zone, instance_resource=instance_config)

                # --- Wait for Operation Completion ---
                logger.info(f"Waiting for instance creation operation {operation.name} to complete...")
                # Need ZoneOperationsClient to wait
                operation_client = compute_v1.ZoneOperationsClient(credentials=credentials)
                # Wait with a timeout (e.g., 5 minutes)
                start_time = time.time()
                timeout_seconds = 300
                while time.time() - start_time < timeout_seconds:
                    op_result = operation_client.get(project=project_id, zone=zone, operation=operation.name)
                    if op_result.status == compute_v1.Operation.Status.DONE:
                        if op_result.error:
                            error_msg = f"Instance creation failed: {op_result.error.errors[0].message if op_result.error.errors else 'Unknown error'}"
                            logger.error(error_msg)
                            raise google_exceptions.GoogleAPICallError(error_msg) # Raise error to be caught below
                        logger.info("Instance creation operation finished successfully.")
                        break
                    time.sleep(10) # Poll every 10 seconds
                else: # Loop finished without break (timeout)
                    logger.error(f"Timeout waiting for instance creation operation {operation.name} to complete.")
                     # Try to delete the potentially half-created instance? Risky.
                    return False

                # --- Get Instance Details (including IP) ---
                instance_details = compute_client.get(project=project_id, zone=zone, instance=instance_name)
                public_ip = "N/A"
                if instance_details.network_interfaces and instance_details.network_interfaces[0].access_configs:
                    public_ip = instance_details.network_interfaces[0].access_configs[0].nat_ip

                self.created_resource_details = {
                    'type': 'GCP Compute Engine VM',
                    'name': instance_name,
                    'id': str(instance_details.id), # ID is uint64, convert to string
                    'project_id': project_id,
                    'zone': zone,
                    'machine_type': machine_type,
                    'public_ip': public_ip,
                    'ssh_user': ssh_user,
                    'ssh_key_private_path': self.ssh_key_paths.get('private')
                }
                logger.info(f"GCP VM Created Successfully:")
                logger.info(f"  Name: {instance_name}")
                logger.info(f"  ID: {instance_details.id}")
                logger.info(f"  IP: {public_ip}")
                logger.info(f"  User: {ssh_user}")
                logger.info(f"  Key File Instruction: Use the generated key at '{self.created_resource_details['ssh_key_private_path']}'")


            except google_exceptions.GoogleAPICallError as e:
                logger.error(f"GCP API error during instance creation or waiting: {e}"); return False
            except Exception as e:
                logger.error(f"Unexpected error during GCP instance creation/wait: {e}", exc_info=True); return False


            # --- Firewall Rule for SSH ---
            firewall_client = compute_v1.FirewallsClient(credentials=credentials)
            ssh_rule_name = "ai-devops-allow-ssh" # Standard name
            # Target instances with the specific tag we added
            target_tag = "ai-devops-instance"

            ssh_rule = compute_v1.Firewall(
                name=ssh_rule_name,
                network="global/networks/default", # Apply to default network
                direction=compute_v1.Firewall.Direction.INGRESS, # Inbound traffic
                priority=1000, # Standard priority
                allowed=[compute_v1.Allowed(
                    ip_protocol="tcp",
                    ports=["22"] # Allow TCP port 22
                )],
                source_ranges=["0.0.0.0/0"], # Allow from any source IP (Restrict in production)
                target_tags=[target_tag] # Apply only to instances with this tag
            )

            try:
                logger.info(f"Ensuring firewall rule '{ssh_rule_name}' allowing SSH to tag '{target_tag}'...")
                # Check if rule exists first (optional but good practice)
                try:
                    firewall_client.get(project=project_id, firewall=ssh_rule_name)
                    logger.info(f"Firewall rule '{ssh_rule_name}' already exists.")
                except google_exceptions.NotFound:
                    logger.info(f"Firewall rule '{ssh_rule_name}' not found. Creating...")
                    fw_op = firewall_client.insert(project=project_id, firewall_resource=ssh_rule)
                    # Wait briefly for firewall rule operation (usually faster than instances)
                    # We can use GlobalOperationsClient here
                    global_op_client = compute_v1.GlobalOperationsClient(credentials=credentials)
                    start_time = time.time()
                    fw_timeout = 60
                    while time.time() - start_time < fw_timeout:
                        fw_op_result = global_op_client.get(project=project_id, operation=fw_op.name)
                        if fw_op_result.status == compute_v1.Operation.Status.DONE:
                            if fw_op_result.error:
                                raise google_exceptions.GoogleAPICallError(f"Firewall rule creation failed: {fw_op_result.error}")
                            logger.info(f"Firewall rule '{ssh_rule_name}' created successfully.")
                            break
                        time.sleep(5)
                    else:
                        logger.warning(f"Timeout waiting for firewall rule '{ssh_rule_name}' creation.")
            except google_exceptions.Conflict:
                logger.info(f"Firewall rule '{ssh_rule_name}' likely created concurrently or already exists (caught conflict).")
            except Exception as fw_e:
                logger.warning(f"Could not ensure SSH firewall rule '{ssh_rule_name}': {fw_e}") # Warn but proceed

            return True # VM creation itself was successful

        except Exception as e: # Catch errors in key gen or image lookup phase
            logger.error(f"Unexpected error during GCP VM setup: {e}", exc_info=True)
            return False
        finally:
            # Cleanup generated SSH key temp dir
            if key_temp_dir and os.path.exists(key_temp_dir):
                try: shutil.rmtree(key_temp_dir, onerror=remove_readonly)
                except Exception as cleanup_e: logger.warning(f"Could not cleanup temp key directory {key_temp_dir}: {cleanup_e}")
            # Clear paths even if cleanup failed directory removal
            self.ssh_key_paths = {}

    def generate_cicd_config(self) -> bool:
        logger.info("Attempting to generate CI/CD pipeline configuration via LLM...")
        if not self.openai_client:
            logger.error("OpenAI client not initialized. Cannot use LLM."); return False

        # --- Determine CI Platform and Target Path ---
        target_ci_path_in_repo = None # Path relative to repo root
        local_save_path = None # Absolute path if saving locally
        repo_info = self.repo_url.lower()

        if self.is_github_repo:
            self.ci_platform = "GitHub Actions"
            target_ci_path_in_repo = '.github/workflows/ai-devops-cicd.yml'
            logger.info(f"Targeting {self.ci_platform}, path in repo: {target_ci_path_in_repo}")
        elif 'gitlab.com' in repo_info:
            self.ci_platform = "GitLab CI"
            target_ci_path_in_repo = '.gitlab-ci.yml'
            logger.info(f"Targeting {self.ci_platform}, path in repo: {target_ci_path_in_repo}")
        elif 'bitbucket.org' in repo_info:
            self.ci_platform = "Bitbucket Pipelines"
            target_ci_path_in_repo = 'bitbucket-pipelines.yml'
            logger.info(f"Targeting {self.ci_platform}, path in repo: {target_ci_path_in_repo}")
        else:
             # Fallback for unknown hosts or when using local clone method
            self.ci_platform = "GitHub Actions" # Default assumption
            target_ci_path_in_repo = '.github/workflows/ai-devops-cicd.yml'
            if self.repo_path: # If we have a local clone path
                workflow_dir = os.path.join(self.repo_path, '.github', 'workflows')
                os.makedirs(workflow_dir, exist_ok=True)
                local_save_path = os.path.join(workflow_dir, 'ai-devops-cicd.yml')
                logger.warning(f"Unknown Git host or using local clone. Defaulting to {self.ci_platform} format. Will save locally to: {local_save_path}")
            else:
                logger.error("Cannot determine local save path for CI/CD config as local repo path is not set.")
                return False

        if not target_ci_path_in_repo: # Should be set by logic above
            logger.error("Could not determine CI/CD output file path within the repository."); return False

        # --- Prepare Context for LLM ---
        resource_details_for_llm = self.selected_resource_details or self.created_resource_details
        target_type = self.resource_configuration.get('type', 'unknown')
        is_vm_like = target_type in ['ec2', 'vm'] # GCP 'vm' or Azure 'vm'

        deploy_ip = resource_details_for_llm.get('public_ip', 'YOUR_SERVER_IP')
        deploy_user = resource_details_for_llm.get('ssh_user') or resource_details_for_llm.get('admin_username', 'YOUR_SSH_USER')
        artifact_name = "app.zip" # Consistent artifact name
        ssh_secret_name = "DEPLOY_SSH_PRIVATE_KEY" # Standardized secret name

        if not is_vm_like:
            deploy_ip = "N/A (Non-VM Target)"
            deploy_user = "N/A (Non-VM Target)"

        logger.info(f"Context for LLM: Stack={self.detected_stack}, Provider={self.cloud_provider}, Target={target_type}, IP={deploy_ip}, User={deploy_user}")

        # Ensure necessary keys exist in resource_details for LLM prompt, even if None/default
        resource_details_for_llm.setdefault('public_ip', 'YOUR_SERVER_IP')
        resource_details_for_llm.setdefault('ssh_user', 'YOUR_SSH_USER')
        resource_details_for_llm.setdefault('admin_username', 'YOUR_SSH_USER') # Check both common keys
        resource_details_for_llm.setdefault('id', 'unknown-id')
        resource_details_for_llm.setdefault('name', 'unknown-name')
        
        # --- Construct the LLM Prompt ---
        prompt = f"""
        Generate a CI/CD pipeline configuration in YAML format for {self.ci_platform}.
        The pipeline should build, test, and **automatically deploy** the application artifact to the target server using SSH/SCP.

        **Context:**
        - Repository URL: {self.repo_url}
        - Detected Technology Stack: {self.detected_stack}
        - Cloud Provider: {self.cloud_provider.upper()}
        - Deployment Target Type: {target_type}
        - Deployment Server IP: {deploy_ip}
        - Deployment SSH User: {deploy_user}
        - CI/CD Secret Name for SSH Key: {ssh_secret_name} (This secret must contain the private SSH key and be configured in the CI/CD platform settings)
        - Build Artifact Name: {artifact_name}
        - Assumed Deployment Script on Server: `~/deploy.sh` (This script should exist in the user's home directory on the server and handle unpacking {artifact_name}, installing dependencies, and restarting the application)

        **Pipeline Requirements:**
        1.  **Trigger:** Configure the pipeline to run on pushes to the `main` or `master` branch.
        2.  **Checkout:** Check out the repository code.
        3.  **Setup Environment:** Set up the necessary runtime environment for the `{self.detected_stack}` stack (e.g., Node.js version '18.x' or '20.x', Python version '3.10' or '3.11', Java JDK '17'). Use recent LTS versions.
        4.  **Install Dependencies:** Run standard commands to install project dependencies (e.g., `npm ci` or `npm install`, `pip install -r requirements.txt`, `mvn -B package -DskipTests`). Handle `package-lock.json` or `yarn.lock` if they exist for Node.js.
        5.  **Build (if applicable):** Run standard build commands (e.g., `npm run build`, `mvn package -DskipTests`). Skip if not typical for the stack (like basic Python/Node scripts without a build step).
        6.  **Test (Optional Placeholder):** Include a placeholder step for running tests (e.g., `npm test`, `python -m unittest discover`). It's okay if it just echoes a message like "Running tests...".
        7.  **Archive:** Create a deployment artifact named `{artifact_name}` containing the necessary files to run the application (e.g., built files (`dist`, `build`, `target`), scripts, `package.json`/`requirements.txt`/`pom.xml`, but EXCLUDE `node_modules`, `venv`, large cache dirs, `.git`). Be specific about included/excluded files based on stack. For Python, include `requirements.txt`. For Node, include `package.json` and `package-lock.json`. For Java, include the JAR/WAR from `target/`.
        8.  **Deploy (Only if target is VM-like: {is_vm_like}):**
            -   **Condition:** This step MUST only run if the target type is VM-like (e.g., {target_type in ['ec2', 'vm']}). If not, skip this step gracefully (e.g., using `if` conditions in the CI syntax).
            -   **Add SSH Key:** Securely load the private key from the `{ssh_secret_name}` secret into the SSH agent or a temporary file (chmod 600). Handle this securely based on the CI platform's best practices.
            -   **SCP Artifact:** Use `scp` to copy the `{artifact_name}` to the server's home directory (`~/{artifact_name}`). Use appropriate flags like `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` for simplicity in a CI environment (add comments acknowledging security implications).
            -   **Execute Remote Script:** Use `ssh` to connect to the server (using the loaded key, user `{deploy_user}`, and IP `{deploy_ip}`) and execute the deployment script: `bash ~/deploy.sh`. Again, use appropriate flags like `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`.
        9.  **Platform Specifics:** Use syntax and recommended actions/plugins appropriate for `{self.ci_platform}` (e.g., `actions/checkout@v4`, `actions/setup-node@v4`, `actions/setup-python@v5`, `actions/setup-java@v4`, `${{{{ secrets.{ssh_secret_name} }}}}` for GitHub Actions). Use `script:` for GitLab CI commands. Use `pipe:` for Bitbucket Pipelines if applicable.

        **Output:**
        Generate **only** the complete and valid YAML configuration content. Do not include any explanations, markdown formatting (like ```yaml), comments outside the YAML structure itself, or introductory/concluding sentences. Ensure correct indentation and syntax for {self.ci_platform}.
        """

        logger.debug(f"LLM Prompt for CI/CD Generation (Truncated):\n{prompt[:600]}...")

        try:
            logger.info("Sending request to OpenAI API for CI/CD configuration...")
            response = self.openai_client.chat.completions.create(
                model="gpt-4o", # Use a capable model
                messages=[
                    {"role": "system", "content": f"You are a DevOps assistant generating {self.ci_platform} YAML configuration for automated application deployment."},
                    {"role": "user", "content": prompt}],
                temperature=0.1 # Low temperature for predictable YAML
            )
            generated_text = response.choices[0].message.content
            logger.debug("LLM Raw Response received for CI/CD config.")

            yaml_content = None
            if "```yaml" in generated_text:
                start = generated_text.find("```yaml") + len("```yaml")
                end = generated_text.find("```", start)
                if end != -1:
                    yaml_content = generated_text[start:end].strip()
                else: # Handle case where closing ``` is missing
                    yaml_content = generated_text[start:].strip()
            elif "```" in generated_text: # Handle cases with just ```
                start = generated_text.find("```") + len("```")
                end = generated_text.find("```", start)
                if end != -1:
                    yaml_content = generated_text[start:end].strip()
                else:
                    yaml_content = generated_text[start:].strip()
            else:
                 # Assume the whole response is YAML if no backticks
                yaml_content = generated_text.strip()
                # Basic sanity check for likely YAML start
                if not any(yaml_content.startswith(kw) for kw in ['name:', 'on:', 'jobs:', 'stages:', 'image:', 'pipelines:']):
                    logger.warning("LLM response did not contain YAML markers and doesn't start with common keywords. Attempting to parse anyway.")


            if not yaml_content:
                logger.error("LLM did not return recognizable YAML content after extraction attempts."); return False

            # --- Validate YAML ---
            try:
                # Load to validate syntax
                yaml.safe_load(yaml_content)
                logger.info("Generated YAML syntax appears valid.")
            except yaml.YAMLError as e:
                logger.error(f"Generated content is not valid YAML: {e}")
                logger.debug(f"--- Invalid YAML Content Start ---\n{yaml_content}\n--- Invalid YAML Content End ---")
                return False

            # --- Commit or Save ---
            commit_message = "feat: Add AI-generated CI/CD pipeline for automated deployment"
            if self.is_github_repo and self.github_client:
                # Try committing via API
                logger.info(f"Attempting to commit CI/CD file '{target_ci_path_in_repo}' via GitHub API...")
                if self._commit_file_via_api(target_ci_path_in_repo, yaml_content, commit_message):
                    self.commit_pushed = True # Mark as pushed via API
                    logger.info("Successfully committed CI/CD config via GitHub API.")
                else:
                    logger.error("Failed to commit automated CI/CD config via API. Saving locally as fallback if possible.")
                    # Fallback to local save if API commit fails and local path exists
                    if local_save_path:
                        try:
                            with open(local_save_path, 'w') as f: f.write(yaml_content)
                            logger.info(f"CI/CD configuration saved locally as fallback to: {local_save_path}")
                            self._add_keys_to_gitignore_local()
                        except Exception as e:
                            logger.error(f"Failed to save CI/CD config locally even as fallback: {e}")
                            return False # Both API and local save failed
                    else:
                         return False # API commit failed, no local path to save to
            elif local_save_path:
                # Save locally if not GitHub API mode or if API commit failed
                try:
                    with open(local_save_path, 'w') as f: f.write(yaml_content)
                    logger.info(f"Generated CI/CD configuration saved locally to: {local_save_path}")
                    self._add_keys_to_gitignore_local() # Ensure keys are ignored before potential local commit
                    # self.commit_pushed will be handled by commit_and_push_local_changes later
                except Exception as e:
                    logger.error(f"Failed to save CI/CD config locally: {e}", exc_info=True)
                    return False
            else:
                 logger.error("Cannot save or commit CI/CD config: Not using GitHub API and no local repo path available.")
                 return False


            # --- Automate Secret Setup for GitHub Actions (if applicable) ---
            # Only attempt if it's a VM-like target, using GitHub API, and we generated keys
            private_key_for_secret = self.ssh_key_paths.get('private') if self.resource_configuration.get('create_new') else None
            # ^ Only use generated key if we created the resource

            if self.is_github_repo and self.github_client and self.repo_object and is_vm_like and private_key_for_secret:
                logger.info(f"Attempting to automatically set GitHub Action secret '{ssh_secret_name}'...")
                try:
                    # Check if PyNaCl is available
                    if nacl is None:
                         raise ImportError("PyNaCl not installed (`pip install pynacl`).")

                    repo = self.repo_object
                    # Check if secret already exists
                    secret_exists = False
                    try:
                        repo.get_secret(ssh_secret_name)
                        logger.info(f"GitHub Action secret '{ssh_secret_name}' already exists. Skipping creation.")
                        secret_exists = True
                        self.ssh_key_secret_set = True # Assume it's correctly set if it exists
                    except UnknownObjectException:
                        logger.info(f"Secret '{ssh_secret_name}' not found. Proceeding to create it.")
                    except GithubException as ge:
                         if ge.status == 404: # Expected if secret doesn't exist
                            logger.info(f"Secret '{ssh_secret_name}' not found (via check). Proceeding to create it.")
                         else:
                            logger.warning(f"Could not check for existing secret '{ssh_secret_name}': {ge}. Attempting creation anyway.")

                    if not secret_exists:
                        # Get the repository's public key for encryption
                        # Use the authenticated PyGithub client's requester method
                        response = self.github_client.requester.requestJsonAndCheck(
                             "GET", f"/repos/{repo.full_name}/actions/secrets/public-key"
                        )
                        if response[0] != 200: # Check status code
                             raise GithubException(response[0], response[1], headers=response[2])
                        public_key_data = response[1] # [status_code, data, headers]
                        key_id = public_key_data['key_id']
                        public_key_b64 = public_key_data['key']

                        # Encrypt the private key content
                        pub_key = PublicKey(public_key_b64.encode('utf-8'), encoder=Base64Encoder) # Key is Base64 encoded
                        sealed_box = SealedBox(pub_key)
                        with open(private_key_for_secret, 'rb') as f:
                            private_key_content_bytes = f.read()

                        encrypted_bytes = sealed_box.encrypt(private_key_content_bytes)
                        encrypted_value_b64 = Base64Encoder.encode(encrypted_bytes).decode('utf-8')

                        # Set the secret via GitHub API
                        secret_data = {
                            "encrypted_value": encrypted_value_b64,
                            "key_id": key_id
                        }
                        put_response = self.github_client.requester.requestJsonAndCheck(
                            "PUT",
                            f"/repos/{repo.full_name}/actions/secrets/{ssh_secret_name}",
                            input=secret_data # Use 'input' for PUT body
                        )
                        # Check response status (expect 201 Created or 204 No Content on update)
                        if put_response[0] not in [201, 204]:
                            raise GithubException(put_response[0], put_response[1], headers=put_response[2])

                        logger.info(f"Successfully set '{ssh_secret_name}' secret via GitHub API.")
                        self.ssh_key_secret_set = True

                except ImportError as e:
                    logger.warning(f"{e} Skipping automatic SSH key secret setup. Please set '{ssh_secret_name}' manually in GitHub secrets.")
                    self.ssh_key_secret_set = False
                except GithubException as e:
                    error_msg = e.data.get('message', 'Unknown GitHub API error') if isinstance(e.data, dict) else str(e.data)
                    logger.error(f"GitHub API error setting secret '{ssh_secret_name}': {e.status} - {error_msg}", exc_info=False) # Less verbose exc_info
                    logger.error("Ensure the PAT has 'repo' scope and Actions secrets write permissions.")
                    self.ssh_key_secret_set = False
                except Exception as e:
                    logger.error(f"Failed to set '{ssh_secret_name}' secret: {e}", exc_info=True)
                    self.ssh_key_secret_set = False
            elif is_vm_like:
                 if not self.is_github_repo or not self.github_client:
                    logger.info("Skipping automatic secret setup: Not using GitHub API.")
                 elif not private_key_for_secret:
                    logger.info(f"Skipping automatic secret setup: Using existing resource or key generation failed. Set '{ssh_secret_name}' manually.")
            else:
                logger.info(f"Target type '{target_type}' does not require SSH key secret. Skipping automatic setup.")

            return True

        except openai.APIError as e: logger.error(f"OpenAI API Error: {e.status_code} - {e.body}"); return False
        except openai.AuthenticationError as e: logger.error(f"OpenAI Authentication Error: {e}"); return False
        except openai.RateLimitError as e: logger.error(f"OpenAI Rate Limit Error: {e}"); return False
        except Exception as e: logger.error(f"LLM interaction error: {e}", exc_info=True); return False

    def _commit_file_via_api(self, file_path: str, content: str, message: str) -> bool:
        """Commits a file to the GitHub repository using the API."""
        if not self.is_github_repo or not self.github_client or not self.repo_object:
            logger.error("Cannot commit via API: GitHub client/repository object not available.")
            return False

        logger.info(f"Attempting to commit file '{file_path}' via GitHub API...")
        try:
            if isinstance(content, bytes):
                content = content.decode('utf-8')
                
            try:
                # Check if file exists to update it, otherwise create it
                existing_file = self.repo_object.get_contents(file_path) # add ref=branch_name?
                logger.info(f"File '{file_path}' exists (SHA: {existing_file.sha}). Updating...")
                update_result = self.repo_object.update_file(
                    path=file_path,
                    message=message,
                    content=content,
                    sha=existing_file.sha
                    # branch=branch_name # Specify branch if needed
                )
                commit_sha = update_result['commit'].sha
                logger.info(f"Successfully updated file '{file_path}' via API. Commit SHA: {commit_sha}")
                return True
            except UnknownObjectException:
                # File doesn't exist, create it
                logger.info(f"File '{file_path}' does not exist. Creating...")
                create_result = self.repo_object.create_file(
                    path=file_path,
                    message=message,
                    content=content
                    # branch=branch_name # Specify branch if needed
                )
                commit_sha = create_result['commit'].sha
                logger.info(f"Successfully created file '{file_path}' via API. Commit SHA: {commit_sha}")
                return True
        except GithubException as e:
            error_msg = e.data.get('message', 'Unknown error') if isinstance(e.data, dict) else str(e.data)
            logger.error(f"GitHub API error committing file '{file_path}': {e.status} - {error_msg}")
            if e.status == 409: logger.error("Conflict occurred (409). Maybe the file was modified concurrently or branch issue?")
            if e.status == 403: logger.error("Permission denied (403). Does the token have 'repo' (or 'contents:write') scope?")
            if e.status == 422: logger.error(f"Unprocessable Entity (422). Validation error: {e.data.get('errors')}")
            # If commit fails, self.commit_pushed remains False (or is set to False)
            return False
        except Exception as e:
            logger.error(f"Unexpected error committing file via API: {e}", exc_info=True)
            return False
    
    def _add_keys_to_gitignore_local(self):
        """Adds generated SSH key filename to .gitignore in the local repo path."""
        if not self.repo_path or not os.path.isdir(self.repo_path):
            logger.debug("Skipping .gitignore update: No local repository path.")
            return

        gitignore_path = os.path.join(self.repo_path, '.gitignore')
        private_key_path = self.ssh_key_paths.get('private')

        if not private_key_path or not os.path.exists(private_key_path):
            logger.debug("Skipping .gitignore update: No private key path recorded or key file doesn't exist.")
            return # No key to ignore

        key_file_name = os.path.basename(private_key_path)
        entry_to_add = f"{key_file_name}\n" # Add newline

        try:
            gitignore_content = ""
            if os.path.exists(gitignore_path):
                with open(gitignore_path, 'r') as f_read:
                    gitignore_content = f_read.read()

            # Check if the exact filename is already present (maybe with different line endings)
            if f"\n{key_file_name}\n" in gitignore_content or gitignore_content.endswith(f"\n{key_file_name}") or gitignore_content == key_file_name:
                 logger.debug(f"'{key_file_name}' seems to be already in .gitignore.")
                 return

            # Append the key filename
            with open(gitignore_path, 'a') as f_append:
                # Add a newline before our entry if the file doesn't end with one
                if gitignore_content and not gitignore_content.endswith('\n'):
                     f_append.write("\n")
                f_append.write(f"\n# AI DevOps Generated Keys (DO NOT COMMIT)\n")
                f_append.write(entry_to_add)
            logger.info(f"Added '{key_file_name}' to local .gitignore at '{gitignore_path}'")

        except Exception as e:
            logger.warning(f"Could not update local .gitignore: {e}")

    def commit_and_push_local_changes(self) -> bool:
        """Commits and pushes changes from the local temporary repo."""
        if not self.repo_path or not os.path.isdir(self.repo_path):
            logger.warning("Skipping local commit/push: No local repository path."); return True # Not a failure state

        logger.info("Attempting to commit and push local changes...")
        # Ensure keys are in gitignore *before* adding files
        self._add_keys_to_gitignore_local()

        try:
            repo = Repo(self.repo_path)

            # Check for changes (CI file, .gitignore)
            if not repo.is_dirty(untracked_files=True):
                logger.info("No local changes detected to commit.");
                self.commit_pushed = False # No push needed if nothing committed
                return True # Still success, nothing to do

            repo.git.add(A=True) # Add all changes (includes .gitignore update if any)
            commit_message = "feat: Add AI-generated CI/CD configuration and ignore keys"
            repo.index.commit(commit_message)
            logger.info("Committed local changes.")

            # Push logic
            pushed = False
            remote_name = 'origin'
            try:
                remote = repo.remote(name=remote_name)
                logger.info(f"Pushing local changes to remote '{remote_name}'...")
                push_infos = remote.push()

                # Check push results for errors
                push_failed = False
                for info in push_infos:
                    if info.flags & (info.ERROR | info.REJECTED | info.REMOTE_REJECTED):
                        logger.error(f"Push failed for ref '{info.local_ref}': {info.summary}")
                        push_failed = True
                if not push_failed:
                    pushed = True
                    logger.info("Local push successful.")
                else:
                    logger.error("Local push failed. Check remote permissions and upstream status.")

            except GitCommandError as pe:
                stderr = pe.stderr.strip()
                logger.error(f"Git push command failed: {stderr}")
                if "Authentication failed" in stderr:
                    logger.error("Authentication failed for push. Ensure SSH key/token is configured correctly for push access.")
                pushed = False
            except ValueError: # Remote 'origin' not found
                logger.error(f"Remote '{remote_name}' not found in the local repository. Cannot push.")
                pushed = False
            except Exception as push_e:
                logger.error(f"An unexpected error occurred during push: {push_e}")
                pushed = False

            self.commit_pushed = pushed
            return True

        except GitCommandError as e:
            logger.error(f"Git commit error: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected local commit/push error: {e}", exc_info=True)
            return False

    def generate_setup_instructions(self) -> str:
        """Generates instructions focusing on CI/CD setup and manual fallbacks."""
        instructions = ["# AI DevOps Setup & Deployment Instructions\n"]

        resource_info = self.created_resource_details or self.selected_resource_details
        target_type = self.resource_configuration.get('type', 'unknown')
        is_vm_like = target_type in ['ec2', 'vm'] # GCP/Azure VM
        ssh_secret_name = "DEPLOY_SSH_PRIVATE_KEY" # Standardized secret name

        # --- Section 1: Overview ---
        instructions.append("## 1. Overview")
        instructions.append(f"- Cloud Provider: {self.cloud_provider.upper() if self.cloud_provider else 'Not Set'}")
        instructions.append(f"- Target Resource Type: {target_type.upper()}")
        resource_action = "Created" if self.resource_configuration.get('create_new') else "Selected Existing"
        resource_name_display = resource_info.get('name', 'N/A')
        instructions.append(f"- Resource: {resource_action} '{resource_name_display}'")
        instructions.append(f"- Detected Stack: {self.detected_stack if self.detected_stack else 'Not Detected'}")

        # CI/CD Pipeline Info
        ci_file_path_display = "N/A"
        if self.ci_platform == "GitHub Actions": ci_file_path_display = '.github/workflows/ai-devops-cicd.yml'
        elif self.ci_platform == "GitLab CI": ci_file_path_display = '.gitlab-ci.yml'
        elif self.ci_platform == "Bitbucket Pipelines": ci_file_path_display = 'bitbucket-pipelines.yml'

        if self.ci_platform:
            commit_status = "automatically committed to your repository via API" if self.commit_pushed and self.is_github_repo else \
                            "committed and pushed from local clone" if self.commit_pushed and not self.is_github_repo else \
                            "generated locally (manual commit/push needed)"
            instructions.append(f"- A basic {self.ci_platform} pipeline configuration (`{ci_file_path_display}`) was generated and {commit_status}.")

            if is_vm_like:
                instructions.append(f"  - **Goal:** This pipeline aims to **automatically deploy** your application to the target server ({target_type}) on pushes to the main/master branch.")
                instructions.append(f"  - **ACTION REQUIRED for Automation:** For automatic deployment to work, you **MUST** configure the `{ssh_secret_name}` secret in your CI/CD provider settings (e.g., GitHub Repository Secrets).")
                instructions.append(f"    - The value of this secret must be the **entire content** of the private SSH key (`.pem` file) required to access the server.")

                # Report on automatic secret setting attempt
                if self.is_github_repo and is_vm_like: # Check if script *should* have tried (GitHub + VM)
                    if self.ssh_key_secret_set:
                        instructions.append(f"    - ✅ The script **successfully attempted** to set the `{ssh_secret_name}` secret automatically via the GitHub API.")
                        instructions.append(f"       Verify this secret in your repository's Settings > Secrets and variables > Actions.")
                    else:
                        # Explain why it might have failed
                        reason = "possible reasons: PyNaCl library not installed, PAT lacks 'secrets' permissions, API error, or secret already existed." if self.ssh_key_paths.get('private') else "automatic setup skipped as an existing VM was selected or key generation failed."
                        instructions.append(f"    - ⚠️ The script **could not** automatically set the `{ssh_secret_name}` secret ({reason}).")
                        instructions.append(f"    - **You MUST set the `{ssh_secret_name}` secret manually.**")
                elif is_vm_like: # VM-like target, but not GitHub or other issue
                    instructions.append(f"    - **You MUST set the `{ssh_secret_name}` secret manually.**")

            else: # Not a VM-like target
                instructions.append(f"  - This pipeline is configured for the `{target_type}` target. Deployment steps may involve different commands (e.g., `aws lambda update-function-code`, `az webapp deploy`). Review the generated YAML (`{ci_file_path_display}`).")
                instructions.append(f"  - **Secrets Required:** Depending on the generated pipeline, you might need to configure secrets for cloud provider authentication (e.g., `AWS_ACCESS_KEY_ID`, `AZURE_CREDENTIALS`) in your CI/CD platform.")

        else:
            instructions.append("- CI/CD configuration generation was skipped or failed.")

        if not self.commit_pushed and self.ci_platform and not self.is_github_repo: # Changes generated locally but not pushed
            instructions.append(f"- **Manual Action:** Since changes were not automatically pushed, manually review, commit, and push the generated CI/CD file (`{ci_file_path_display}`) and any `.gitignore` changes from the temporary local clone (if it wasn't cleaned up).")

        instructions.append("- You may need a local SSH client (for VMs) or cloud provider CLI for manual access or troubleshooting.")

        # --- Section 2: SSH Key Details (If VM-like target) ---
        if is_vm_like:
            private_key_path_generated = self.ssh_key_paths.get('private') if self.resource_configuration.get('create_new') else None
            private_key_path_display = "N/A"
            public_key_path_display = "N/A"
            key_source_info = ""

            if private_key_path_generated and os.path.exists(private_key_path_generated):
                # Key was generated by the script for a NEW resource
                private_key_path_display = private_key_path_generated
                public_key_path_display = self.ssh_key_paths.get('public', f"{private_key_path_display}.pub") # Use stored public path
                key_source_info = "(Generated by Script)"
                instructions.append("\n## 2. SSH Key Details " + key_source_info)
                instructions.append(f"- An SSH key pair was generated to access the **newly created** resource.")
                # IMPORTANT: Keys are temporary in the API context. User needs to save the private key content *now*.
                instructions.append(f"  - **ACTION REQUIRED: SAVE THE PRIVATE KEY CONTENT BELOW.**")
                instructions.append(f"    It was generated temporarily and will be deleted after this process finishes.")
                try:
                    with open(private_key_path_display, 'r') as f: key_content = f.read()
                    instructions.append(f"    ```\n{key_content}\n```")
                except Exception as key_read_e:
                    instructions.append(f"    **Error reading temporary private key file:** {key_read_e}. Key might already be cleaned up.")
                    key_content = None # Flag that content wasn't retrieved

                key_name_in_cloud = resource_info.get('key_pair_name', self.ssh_key_paths.get('key_name', 'N/A')) # Get name used in cloud
                instructions.append(f"  - **Key Name Reference:** `{key_name_in_cloud}` (This name might be used in the cloud provider console).")
                if key_content:
                    instructions.append(f"  - **Use the private key content above** when setting the `{ssh_secret_name}` secret in your CI/CD platform.")
                else:
                    instructions.append(f"  - **Cannot display private key content.** You will need to regenerate or manually configure access if you didn't save it.")

            else: # Existing VM was selected OR key wasn't generated/found by this script run
                instructions.append("\n## 2. SSH Key Details (Existing VM / Manual Key)")
                instructions.append("- You selected an existing VM or the key was not generated by this script run.")
                instructions.append("- You must use the **correct existing private key** that corresponds to the public key already authorized on that VM.")
                instructions.append(f"- **Action Required:** Locate your existing private key file for the VM '{resource_name_display}'.")
                private_key_path_display = "/path/to/your/existing_private_key.pem (Replace this)" # Placeholder
                instructions.append(f"- **Use the content of YOUR existing private key file** when setting the `{ssh_secret_name}` secret in your CI/CD platform.")


        # --- Section 3: Triggering Deployment & Manual Fallback ---
        instructions.append("\n## 3. Deployment")
        instructions.append("\n### 3.1 Automated Deployment (Recommended)")
        instructions.append(f"1.  **Ensure Secrets are Set:** Verify the required secrets (`{ssh_secret_name}` for VMs, possibly cloud credentials for other types) are configured in your CI/CD platform (e.g., GitHub Actions secrets). See Section 1 & 2.")
        if not self.commit_pushed and self.ci_platform:
            instructions.append(f"2.  **Push Changes:** Manually commit and push the CI/CD configuration file (`{ci_file_path_display}`) and any other necessary changes (like `.gitignore`) to your `main` or `master` branch.")
        else:
            instructions.append(f"2.  **Trigger Pipeline:** Push a commit to your `main` or `master` branch.")
        instructions.append(f"3.  **Monitor Pipeline:** Check the execution status and logs in your {self.ci_platform} interface.")

        # Manual steps only relevant for VM-like targets
        if is_vm_like:
            instructions.append("\n### 3.2 Manual Deployment (Fallback / Testing)")
            instructions.append("If automated deployment fails or you need to deploy manually:")
            ssh_user = resource_info.get('ssh_user') or resource_info.get('admin_username', 'YOUR_SSH_USER')
            public_ip = resource_info.get('public_ip', 'YOUR_SERVER_IP')

            # Validate IP and User before showing commands
            if public_ip == 'N/A' or public_ip == 'YOUR_SERVER_IP' or not public_ip:
                instructions.append("- ⚠️ Could not determine the Public IP address. Find it in your cloud provider console.")
                public_ip = "YOUR_SERVER_IP" # Reset placeholder
            if ssh_user == 'N/A' or ssh_user == 'YOUR_SSH_USER' or not ssh_user:
                instructions.append("- ⚠️ Could not determine the SSH username. Common defaults: `ubuntu` (Ubuntu), `ec2-user` (Amazon Linux), `azureuser` (Azure), `gcpuser` (GCP). Find the correct one for your VM.")
                ssh_user = "YOUR_SSH_USER" # Reset placeholder

            instructions.append(f"1.  **Locate Private Key:** You need the private key file corresponding to the VM. If generated by this script, you should have saved its content (see Section 2). If existing, use your key file: `{private_key_path_display}`.")
            instructions.append(f"2.  **Save Key Content:** If generated by the script, save the private key content shown in Section 2 to a local file (e.g., `~/.ssh/ai_devops_key.pem`).")
            instructions.append(f"3.  **Set Permissions:** On Linux/macOS/WSL: `chmod 600 /path/to/your/private_key.pem`")
            instructions.append(f"4.  **Build Artifact:** Create the deployment artifact locally (e.g., `zip -r app.zip . -x node_modules/\* .git/\* venv/\*`). Adjust based on your stack.")
            instructions.append(f"5.  **Copy Artifact (SCP):**")
            instructions.append(f"    ```bash")
            instructions.append(f"    # Replace /path/to/your/private_key.pem with the actual path")
            instructions.append(f"    scp -i /path/to/your/private_key.pem -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ./app.zip {ssh_user}@{public_ip}:~/")
            instructions.append(f"    ```")
            instructions.append(f"6.  **SSH and Deploy:**")
            instructions.append(f"    ```bash")
            instructions.append(f"    # Replace /path/to/your/private_key.pem with the actual path")
            instructions.append(f"    ssh -i /path/to/your/private_key.pem -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {ssh_user}@{public_ip} 'bash ~/deploy.sh'")
            instructions.append(f"    ```")
            instructions.append(f"    (Ensure `~/deploy.sh` exists on the server and performs the necessary deployment steps - see Section 4).")

        # --- Section 4: Next Steps ---
        instructions.append("\n## 4. Next Steps & Troubleshooting")
        if is_vm_like:
            instructions.append("- **Create `deploy.sh` on Server:** If it doesn't exist, create `~/deploy.sh` on the target VM (`" + resource_name_display + "`). This script should handle:")
            instructions.append("  - Unpacking the artifact (e.g., `unzip -o ~/app.zip -d /opt/myapp`)")
            instructions.append("  - Navigating to the app directory (`cd /opt/myapp`)")
            instructions.append("  - Installing/updating dependencies (e.g., `npm ci --production`, `pip install -r requirements.txt`)")
            instructions.append("  - Building if necessary (e.g., `npm run build`)")
            instructions.append("  - Restarting your application (e.g., using `pm2`, `systemd`, `docker-compose` etc.)")
            instructions.append("  - Example basic `deploy.sh` structure:")
            instructions.append("    ```bash\n    #!/bin/bash\n    set -e # Exit on error\n    APP_DIR=\"/opt/myapp\"\n    ARTIFACT=\"~/app.zip\"\n    echo \"Deploying artifact $ARTIFACT to $APP_DIR...\"\n    mkdir -p $APP_DIR\n    unzip -o $ARTIFACT -d $APP_DIR\n    cd $APP_DIR\n    echo \"Installing dependencies...\"\n    # Add install command based on stack (npm, pip, etc.)\n    # npm ci --production\n    # pip install -r requirements.txt\n    echo \"Restarting application...\"\n    # Add restart command (pm2 reload myapp, systemctl restart myservice, etc.)\n    echo \"Deployment complete.\"\n    ```")
        instructions.append("- **Check Pipeline Logs:** Carefully review the CI/CD pipeline logs in {self.ci_platform} for errors.")
        if is_vm_like:
            instructions.append("- **Check Server Logs:** If deployment runs but the app fails, check application logs (e.g., in `/var/log`, `journalctl`, or `pm2 logs`) and web server logs (nginx/apache) on the VM.")
        else:
            instructions.append(f"- **Check Cloud Service Logs:** Review logs for the specific cloud service ({target_type}) in the {self.cloud_provider.upper()} console.")
        instructions.append(f"- **Consult Documentation:** Review {self.ci_platform} docs and {self.cloud_provider.upper()} {target_type} deployment documentation if the generated pipeline needs adjustments.")

        return "\n".join(instructions)
    
    def cleanup(self):
        """Cleans up temporary resources like cloned repos and generated keys."""
        # Clean up local repo clone first
        if self.repo_path and os.path.isdir(self.repo_path):
            logger.info(f"Cleaning up temporary local directory: {self.repo_path}")
            try:
                # shutil.rmtree might fail on Windows due to lingering file handles esp. from git
                # Retry logic or more robust deletion might be needed in edge cases
                shutil.rmtree(self.repo_path, onerror=remove_readonly)
                logger.info(f"Successfully cleaned up repo directory: {self.repo_path}")
            except Exception as e:
                logger.error(f"Error removing temporary repo directory {self.repo_path}: {e}")
            finally:
                 # Ensure path is cleared from state even if deletion failed
                self.repo_path = None
        else:
            logger.debug("Skipping repo cleanup: No temporary local repository path set or dir not found.")

        # Clean up generated SSH keys temp directory
        key_temp_dir = self.ssh_key_paths.get('temp_dir')
        if key_temp_dir and os.path.isdir(key_temp_dir):
            logger.info(f"Cleaning up temporary key directory: {key_temp_dir}")
            try:
                shutil.rmtree(key_temp_dir, onerror=remove_readonly)
                logger.info(f"Successfully cleaned up key directory: {key_temp_dir}")
            except Exception as e:
                logger.error(f"Error removing temporary key directory {key_temp_dir}: {e}")
            # Clear all key paths from state after attempting cleanup
            finally:
                self.ssh_key_paths = {}
        else:
            logger.debug("Skipping key cleanup: No temporary key directory recorded or dir not found.")

    def execute_workflow(self) -> Tuple[bool, str]:
        """
        Runs the main workflow steps after configuration is set.
        Returns (success_status, result_message_or_instructions).
        """
        self.commit_pushed = False # Reset status for this run
        final_result = "Workflow execution failed."
        success = False
        start_time = time.time()

        try:
            logger.info("Starting AI DevOps Automator workflow execution...")

            # --- Pre-checks ---
            if not self.repo_url: return False, "Git repository URL not set."
            if not self.cloud_provider: return False, "Cloud provider not set."
            if not self.resource_configuration: return False, "Resource configuration not set."
            if not self.detected_stack: # Stack detection is crucial for CI/CD
                logger.info("Stack not detected yet. Running detection step first...")
                if not self.access_repository_and_detect_stack():
                     # Cleanup might have occurred in access_repo method on failure
                    return False, "Failed to access repository or detect stack before main execution."
                if not self.detected_stack or self.detected_stack == 'unknown':
                    logger.warning("Stack detection ran, but result is unknown. CI/CD generation might be inaccurate.")
                     # Proceed, but with caution.

            logger.info(f"Workflow starting with: Repo={self.repo_url}, Provider={self.cloud_provider}, Stack={self.detected_stack}, Target={self.resource_configuration.get('type')}, CreateNew={self.resource_configuration.get('create_new')}")

            # --- Step 1: Create Resource (if configured) ---
            if self.resource_configuration.get('create_new', False):
                 logger.info("Executing Step: Create new cloud resource...")
                 create_success = False
                 res_type = self.resource_configuration.get('type')
                 try:
                    if self.cloud_provider == 'aws':
                        session = self._get_aws_session()
                        if not session: raise Exception("Failed to get AWS session for creation.")
                        if res_type == 'ec2': create_success = self._create_aws_ec2_instance(session.client('ec2'))
                        elif res_type == 'ecs': create_success = self._create_aws_ecs_cluster(session.client('ecs'))
                        elif res_type == 'lambda': create_success = self._create_aws_lambda_function(session.client('lambda'), session.client('iam'))
                        else: raise NotImplementedError(f"AWS resource creation for type '{res_type}' not implemented.")
                    elif self.cloud_provider == 'azure':
                        cred = self._get_azure_credential()
                        sub_id = self.cloud_credentials.get('subscription_id')
                        if not cred or not sub_id: raise Exception("Failed to get Azure credentials for creation.")
                        if res_type == 'vm':
                            create_success = self._create_azure_vm(
                                azure.mgmt.compute.ComputeManagementClient(cred, sub_id),
                                azure.mgmt.network.NetworkManagementClient(cred, sub_id),
                                azure.mgmt.resource.ResourceManagementClient(cred, sub_id)
                            )
                        # Add App Service creation if desired
                        else: raise NotImplementedError(f"Azure resource creation for type '{res_type}' not implemented.")
                    elif self.cloud_provider == 'gcp':
                        cred, proj_id = self._get_gcp_credential()
                        if not cred or not proj_id: raise Exception("Failed to get GCP credentials for creation.")
                        if res_type == 'vm':
                            create_success = self._create_gcp_vm(
                                compute_v1.InstancesClient(credentials=cred), cred, proj_id
                            )
                        # Add Cloud Run creation if desired
                        else: raise NotImplementedError(f"GCP resource creation for type '{res_type}' not implemented.")

                    if not create_success:
                        # Creation method should have logged specifics
                        raise Exception(f"Resource creation function for '{res_type}' reported failure.")
                    logger.info(f"Successfully created NEW {res_type} resource.")
                 except Exception as creation_e:
                    logger.error(f"Error during resource creation phase: {creation_e}", exc_info=True)
                    # Don't cleanup here, let finally block handle it
                    return False, f"Failed during resource creation: {creation_e}"
            else:
                logger.info("Skipping resource creation (existing resource selected or configured).")

            # --- Step 2: Generate CI/CD Config ---
            logger.info("Executing Step: Generate CI/CD configuration...")
            if not self.generate_cicd_config():
                # generate_cicd_config handles API commit or local save attempts
                # and sets self.commit_pushed if API commit succeeds
                logger.error("Failed to generate and save/commit CI/CD configuration.")
                # Don't cleanup here
                return False, "Failed to generate or commit CI/CD configuration."
            logger.info("CI/CD configuration generated and saved/committed.")


            # --- Step 3: Commit/Push local changes (if NOT using GitHub API or API commit failed) ---
            should_push_local = not (self.is_github_repo and self.commit_pushed)
            # Also check if local repo path exists (meaning clone method was used)
            if should_push_local and self.repo_path and os.path.isdir(self.repo_path):
                logger.info("Executing Step: Commit and push local changes...")
                if not self.commit_and_push_local_changes():
                    # commit_and_push sets self.commit_pushed
                    logger.warning("Failed to commit or push local changes. Instructions will indicate manual steps needed.")
                    # Proceed to generate instructions, but push status is known via self.commit_pushed
                else:
                    logger.info("Local changes committed and pushed successfully (if any changes were detected).")
            elif should_push_local:
                logger.debug("Skipping local commit/push step: Not using GitHub API commit, but no local repo path available.")


            # --- Step 4: Generate Final Instructions ---
            logger.info("Executing Step: Generate setup instructions...")
            setup_instructions = self.generate_setup_instructions()
            final_result = setup_instructions
            success = True

            total_time = time.time() - start_time
            logger.info(f"Workflow execution completed successfully in {total_time:.2f} seconds.")
            return success, final_result

        except Exception as e:
            logger.error(f"An unexpected error occurred in the main workflow: {e}", exc_info=True)
            # Cleanup happens in finally block
            return False, f"An unexpected error occurred during workflow execution: {e}"
        finally:
            # Final cleanup, regardless of success/failure within try block
            logger.info("Executing final cleanup...")
            self.cleanup()
            logger.info("Cleanup finished.")
            
app = FastAPI(
    title="AI DevOps Automator API",
    description="API to automate Git repo analysis, cloud resource provisioning, and CI/CD setup.",
    version="0.1.0",
)   

origins = [
    "http://localhost",
    "http://localhost:3000", # Common React dev port
    "http://localhost:8080", # Common Vue dev port
    "http://127.0.0.1:3000",
    # Add deployed frontend URL in production
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Allows all methods
    allow_headers=["*"], # Allows all headers
)

sessions: Dict[str, AIDevOpsAutomator] = {}

class StartResponse(BaseModel):
    session_id: str

class StatusResponse(BaseModel):
    success: bool
    message: str

class GitInfoRequest(BaseModel):
    repo_url: str = Field(..., examples=["https://github.com/user/repo.git"])
    # Use SecretStr for tokens to prevent accidental logging by FastAPI/Pydantic
    git_token: Optional[SecretStr] = Field(None, examples=["glpat-xxxxxxxxxxxx"])

class CloudProviderEnum(str, Enum):
    aws = "aws"
    azure = "azure"
    gcp = "gcp"

class CloudInfoRequest(BaseModel):
    provider: CloudProviderEnum
    # Keep credentials flexible for now, but add examples
    credentials: Dict[str, Any] = Field(..., examples=[
        {"type": "profile", "profile": "default", "region": "us-east-1"},
        {"type": "keys", "access_key": "AKI...", "secret_key": "...", "region": "us-west-2"},
        {"type": "service_principal", "tenant_id": "...", "client_id": "...", "client_secret": "...", "subscription_id": "..."},
        {"type": "application_default", "project_id": "my-gcp-project"},
    ])
    
class ResourceConfigRequest(BaseModel):
    # Keep config flexible, add examples
    config: Dict[str, Any] = Field(..., examples=[
        {"type": "ec2", "create_new": True, "instance_type": "t2.micro", "instance_name": "api-instance", "region": "us-west-2"},
        {"type": "vm", "create_new": False, "vm_name": "existing-azure-vm", "resource_group": "prod-rg", "location": "eastus", "selected_details": {"id": "...", "name": "existing-azure-vm"}},
        {"type": "ecs", "create_new": False, "cluster_name": "prod-cluster", "region": "eu-central-1"},
    ])

class ExecuteResponse(BaseModel):
    success: bool
    result: str
    
# --- Helper Function to Get Session ---
def get_session(session_id: str) -> AIDevOpsAutomator:
    """Retrieves the automator instance for a given session ID."""
    automator = sessions.get(session_id)
    if not automator:
        api_logger.warning(f"Session ID not found: {session_id}")
        raise HTTPException(status_code=404, detail="Session ID not found")
    return automator

# --- API Endpoints ---
@app.post("/workflow/start", response_model=StartResponse, tags=["Workflow"])
async def start_workflow():
    """Initiates a new workflow session."""
    session_id = str(uuid.uuid4())
    api_logger.info(f"Starting new workflow session: {session_id}")
    try:
        sessions[session_id] = AIDevOpsAutomator()
        api_logger.info(f"AIDevOpsAutomator instance created for session {session_id}")
    except Exception as e:
        api_logger.error(f"Failed to initialize AIDevOpsAutomator for session {session_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to initialize session: {e}")
    return StartResponse(session_id=session_id)

@app.post("/workflow/{session_id}/git", response_model=StatusResponse, tags=["Workflow Configuration"])
async def set_git_info(
    session_id: str = Path(..., description="The unique ID for the workflow session"),
    git_info: GitInfoRequest = Body(...)
):
    """Sets the Git repository information for the session."""
    api_logger.info(f"Received request to set Git info for session: {session_id}")
    automator = get_session(session_id)
    try:
        success = automator.set_git_info(git_info.repo_url, git_info.git_token)
        if success:
            api_logger.info(f"Git info set successfully for session: {session_id}")
            return StatusResponse(success=True, message="Git info set successfully.")
        else:
            api_logger.error(f"Failed to set Git info for session {session_id} (check logs for details).")
            # Automator method logs specifics
            raise HTTPException(status_code=400, detail="Failed to set Git info. Check logs for details.")
    except Exception as e:
        api_logger.error(f"Error setting Git info for session {session_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error setting Git info: {e}")

@app.post("/workflow/{session_id}/cloud", response_model=StatusResponse, tags=["Workflow Configuration"])
async def set_cloud_info(
    session_id: str = Path(..., description="The unique ID for the workflow session"),
    cloud_info: CloudInfoRequest = Body(...)
):
    """Sets the Cloud provider and credentials for the session."""
    api_logger.info(f"Received request to set Cloud info for session: {session_id} (Provider: {cloud_info.provider})")
    automator = get_session(session_id)
    try:
        # Pass the raw dictionary, including potential SecretStr objects
        success = automator.set_cloud_info(cloud_info.provider.value, cloud_info.credentials)
        if success:
            api_logger.info(f"Cloud info set successfully for session: {session_id}")
            return StatusResponse(success=True, message="Cloud info set successfully.")
        else:
            api_logger.error(f"Failed to set Cloud info for session {session_id} (check logs).")
            raise HTTPException(status_code=400, detail="Failed to set Cloud info. Check credentials and logs.")
    except Exception as e:
        api_logger.error(f"Error setting Cloud info for session {session_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error setting Cloud info: {e}")

@app.post("/workflow/{session_id}/resource", response_model=StatusResponse, tags=["Workflow Configuration"])
async def set_resource_config(
    session_id: str = Path(..., description="The unique ID for the workflow session"),
    resource_req: ResourceConfigRequest = Body(...)
):
    """Sets the target cloud resource configuration for the session."""
    api_logger.info(f"Received request to set Resource config for session: {session_id}")
    automator = get_session(session_id)
    if not automator.cloud_provider:
         # This log message matches what you see
        api_logger.warning(f"Attempted to set resource config before cloud provider for session {session_id}")
        raise HTTPException(status_code=400, detail="Cloud provider must be set before resource configuration.")
    try:
        success = automator.set_resource_config(resource_req.config)
        if success:
            api_logger.info(f"Resource config set successfully for session: {session_id}")
            return StatusResponse(success=True, message="Resource configuration set successfully.")
        else:
            # ... (error handling if automator.set_resource_config returns False) ...
            api_logger.error(f"Failed to set resource config for session {session_id} (check logs).")
            raise HTTPException(status_code=400, detail="Failed to set resource configuration. Check config and logs.")
    except Exception as e:
        api_logger.error(f"Error setting resource config for session {session_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error setting resource config: {e}")

@app.post("/workflow/{session_id}/execute", response_model=ExecuteResponse, tags=["Workflow Execution"])
async def execute_workflow(
    session_id: str = Path(..., description="The unique ID for the workflow session")
):
    """
    Executes the main AI DevOps workflow (detection, creation, generation).
    This can be a long-running operation.
    """
    api_logger.info(f"Received request to EXECUTE workflow for session: {session_id}")
    automator = get_session(session_id)
    if not automator.repo_url:
         raise HTTPException(status_code=400, detail="Git info not set for this session.")
    if not automator.cloud_provider:
         raise HTTPException(status_code=400, detail="Cloud info not set for this session.")
    if not automator.resource_configuration:
         raise HTTPException(status_code=400, detail="Resource configuration not set for this session.")

    api_logger.info(f"Executing workflow for session {session_id} in background thread...")
    try:
        # Run the synchronous workflow method in a separate thread
        success, result = await asyncio.to_thread(automator.execute_workflow)
        api_logger.info(f"Workflow execution finished for session {session_id}. Success: {success}")

        if success:
            return ExecuteResponse(success=True, result=result)
        else:
            # Raise HTTPException so FastAPI returns a proper error response
            # The 'result' string contains the error message from the workflow
            api_logger.error(f"Workflow execution failed for session {session_id}: {result}")
            raise HTTPException(status_code=500, detail=f"Workflow execution failed: {result}")

    except Exception as e:
        # Catch unexpected errors during the threaded execution or response handling
        api_logger.error(f"Unexpected error during execute_workflow for session {session_id}: {e}", exc_info=True)
        # Perform cleanup in case of unexpected error during execution phase
        try:
            await asyncio.to_thread(automator.cleanup)
            api_logger.info(f"Performed cleanup for session {session_id} after execution error.")
        except Exception as cleanup_e:
            api_logger.error(f"Error during cleanup after execution error for session {session_id}: {cleanup_e}")
        raise HTTPException(status_code=500, detail=f"Internal server error during workflow execution: {e}")

@app.delete("/workflow/{session_id}", response_model=StatusResponse, tags=["Workflow"])
async def delete_workflow_session(
    session_id: str = Path(..., description="The unique ID for the workflow session to delete")
):
    """Cleans up and deletes a workflow session and its temporary resources."""
    api_logger.info(f"Received request to DELETE session: {session_id}")
    automator = get_session(session_id) # Raises 404 if not found

    try:
        # Run cleanup in a thread as it involves file I/O
        await asyncio.to_thread(automator.cleanup)
        api_logger.info(f"Cleanup successful for session {session_id}.")
    except Exception as e:
        api_logger.error(f"Error during cleanup for session {session_id}: {e}", exc_info=True)
        # Don't necessarily fail the delete request, but log the cleanup error

    # Remove session from memory
    if session_id in sessions:
        del sessions[session_id]
        api_logger.info(f"Session {session_id} removed from memory.")
        return StatusResponse(success=True, message="Session cleaned up and deleted.")
    else:
        # Should have been caught by get_session, but defensive check
        api_logger.warning(f"Session {session_id} not found in memory for deletion, though get_session succeeded initially.")
        return StatusResponse(success=False, message="Session already deleted or not found in memory.")

# --- Optional: Root endpoint for health check ---
@app.get("/", tags=["Health Check"])
async def read_root():
    return {"message": "AI DevOps Automator API is running."}

if __name__ == "__main__":
    import uvicorn
    # Check for required libraries before starting server
    missing_libs = []
    # Add checks for ALL required libraries (FastAPI, Uvicorn, GitPython, boto3, etc.)
    try: import fastapi
    except ImportError: missing_libs.append("fastapi")
    try: import uvicorn
    except ImportError: missing_libs.append("uvicorn[standard]") # [standard] includes websockets etc.
    # ... (Add all other imports from the top of the file) ...
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
    try: import google.cloud.compute_v1  
    except ImportError: missing_libs.append("google-cloud-compute")
    try: import google.auth
    except ImportError: missing_libs.append("google-auth")
    try: import cryptography
    except ImportError: missing_libs.append("cryptography")
    try: import openai
    except ImportError: missing_libs.append("openai")
    try: import github  
    except ImportError: missing_libs.append("PyGithub")
    try: import nacl
    except ImportError: missing_libs.append("pynacl")

    if missing_libs:
        print(f"Error: Missing required Python package(s): {', '.join(missing_libs)}")
        print("Please install them, for example:")
        print(f"pip install {' '.join(missing_libs)}")
        exit(1)

    print("Starting AI DevOps Automator API server...")
    print("Open http://127.0.0.1:8000/docs for API documentation.")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
 