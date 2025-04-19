# AI DevOps Automator 🤖

This Python script automates the initial setup of cloud infrastructure and generates a basic CI/CD pipeline configuration, leveraging AI (OpenAI GPT) for pipeline generation. It aims to streamline the process of getting a project skeleton deployed to AWS, Azure, or GCP.

## Overview

The tool performs the following key steps:

1.  **Connects to Git:** Clones or accesses a Git repository (public or private, HTTPS/SSH). Uses the GitHub API for enhanced features if a GitHub HTTPS URL and PAT are provided.
2.  **Detects Stack:** Analyzes repository files to determine the primary technology stack (e.g., Node.js, Python, Java, Docker).
3.  **Configures Cloud:** Collects cloud provider credentials (AWS, Azure, GCP) through various secure methods.
4.  **Manages Resources:** Allows selecting an existing deployment target (VM, ECS Cluster, Lambda, App Service, Cloud Run) or configuring and **creating** a new one (VMs, ECS Cluster, Lambda Function).
5.  **Generates SSH Keys:** Creates SSH key pairs when provisioning new VM-based resources and configures the VM to use them.
6.  **Generates CI/CD:** Uses OpenAI (GPT-4o) to generate a CI/CD pipeline configuration (currently focused on GitHub Actions) tailored to the detected stack and chosen cloud resource. The generated pipeline emphasizes providing **manual deployment steps** for the user to execute using the generated SSH key.
7.  **Commits Configuration:** Commits the generated CI/CD workflow file back to the repository (directly via API for GitHub, or locally for other repo types). It also updates `.gitignore` locally to exclude generated private keys.
8.  **Sets GitHub Secret (Optional):** If using GitHub Actions and PyNaCl is installed, it attempts to automatically encrypt and set the `DEPLOY_SSH_PRIVATE_KEY` secret required by the generated workflow.
9.  **Provides Instructions:** Outputs detailed instructions on how to use the generated SSH key for manual access and deployment, and next steps for monitoring the CI/CD pipeline.

## Features

*   Supports AWS, Azure, and Google Cloud Platform (GCP).
*   Multiple authentication methods for each cloud provider.
*   Technology stack detection for common languages/frameworks.
*   Option to use existing cloud resources or create new ones:
    *   **AWS:** EC2 Instance, ECS Cluster, Lambda Function
    *   **Azure:** Virtual Machine (VM), App Service (configuration only)
    *   **GCP:** Compute Engine (VM), Cloud Run (configuration only)
*   Automatic SSH key generation and management for new VMs.
*   AI-powered generation of CI/CD pipeline configuration (GitHub Actions focus).
*   Direct commit of CI/CD files to GitHub repositories via API (requires PAT).
*   Local commit and optional push for non-GitHub or SSH-cloned repositories.
*   Automatic setup of `DEPLOY_SSH_PRIVATE_KEY` secret in GitHub Actions (best effort, requires PyNaCl).
*   Clear setup and manual deployment instructions provided as output.
*   Temporary file cleanup.

## Prerequisites

*   **Python:** 3.7+ recommended.
*   **Pip:** Python package installer.
*   **Git:** Git command-line tool must be installed and in your PATH.
*   **Cloud Provider Access:** You need an account with the chosen cloud provider (AWS/Azure/GCP) and appropriate permissions to list, create, and manage resources (VMs, networking, IAM roles, etc.).
*   **OpenAI API Key:** An API key from OpenAI is required for CI/CD generation. The script expects this key to be set in the `OPENAI_API_KEY` environment variable.
*   **GitHub Personal Access Token (PAT) (Optional but Recommended):**
    *   Required if you want the script to interact with a GitHub repository via its API (for listing files without cloning, committing files directly, setting secrets).
    *   The PAT needs the `repo` scope (for private and public repos) or `public_repo` (for public repos only).
*   **Local SSH Setup (Optional):** Required if you intend to clone repositories using the SSH URL format. Ensure your SSH keys are configured correctly locally.

## Installation

1.  **Clone the repository (or download the script):**
    ```bash
    git clone <your-repo-url> # Or just have llm.py
    cd <repo-directory>
    ```

2.  **Install required Python packages:**
    ```bash
    pip install GitPython PyYAML boto3 azure-identity azure-mgmt-resource azure-mgmt-compute azure-mgmt-network google-cloud-compute google-auth cryptography openai PyGithub pynacl
    ```
    *(Note: You might need to adjust based on specific OS requirements for cryptography/pynacl.)*

## Configuration

*   **Set OpenAI API Key:** Before running the script, set the `OPENAI_API_KEY` environment variable:
    *   **Linux/macOS:**
        ```bash
        export OPENAI_API_KEY='your_openai_api_key'
        ```
    *   **Windows (Command Prompt):**
        ```bash
        set OPENAI_API_KEY=your_openai_api_key
        ```
    *   **Windows (PowerShell):**
        ```bash
        $env:OPENAI_API_KEY='your_openai_api_key'
        ```

## Usage

1.  **Run the script:**
    ```bash
    python llm.py [options]
    ```

2.  **Follow the interactive prompts:**
    *   Enter the Git repository URL.
    *   Provide a GitHub PAT if using a GitHub HTTPS URL and want API integration.
    *   Select your cloud provider (AWS, Azure, GCP).
    *   Choose your authentication method and provide the necessary credentials/details.
    *   Select the type of cloud resource to target (e.g., EC2, VM, Lambda).
    *   Choose whether to use an existing resource or create a new one.
    *   Configure details for the new resource if creating one (e.g., instance type, VM size, names).

3.  **Review the output:** The script will perform the actions and finally print detailed setup and manual deployment instructions.

**Command-line Options:**

*   `--verbose` or `-v`: Enable detailed debug logging.
*   `--cleanup-repo`: Force cleanup of the temporary local repository clone, even if a local commit/push failed.

## Workflow Summary

1.  Collect Git repository URL and credentials (token/PAT).
2.  Access repository (via API for GitHub HTTPS + PAT, otherwise clone locally).
3.  Detect technology stack.
4.  Collect cloud provider choice and credentials.
5.  Configure deployment target: Select existing resource or configure parameters for a new one.
6.  **If creating new:** Provision the cloud resource (e.g., VM, Cluster, Function), including generating SSH keys for VMs.
7.  Generate CI/CD YAML using OpenAI based on stack and target resource.
8.  Commit CI/CD file: Use GitHub API if available, otherwise commit locally.
9.  **If GitHub API:** Attempt to set `DEPLOY_SSH_PRIVATE_KEY` secret.
10. **If local commit:** Attempt to push changes.
11. Generate and display final setup/deployment instructions.
12. Clean up temporary local repository clone (unless disabled or push failed without `--cleanup-repo`).

## Supported Technologies & Services

*   **Detected Stacks:** Node.js, Python, Java, GoLang, .NET, PHP, Rust, Docker (basic detection).
*   **Cloud Providers:** AWS, Azure, GCP.
*   **Cloud Services (Target):**
    *   AWS: EC2, ECS, Lambda
    *   Azure: VM, App Service (config only)
    *   GCP: Compute Engine VM, Cloud Run (config only)
*   **CI/CD Platform:** GitHub Actions (primary focus for generation). Can generate GitLab CI/Bitbucket Pipelines format if repo URL suggests it, but testing and secret setup are focused on GitHub Actions.

## Important Considerations & Limitations

*   **Security:**
    *   **Cloud Credentials:** Handled via standard SDK methods. Ensure the environment where you run the script is secure.
    *   **Git Tokens/PATs:** Handled via `getpass` for input, but be mindful of shell history if pasting directly. Use tokens with the minimum required scope.
    *   **SSH Keys:** Private keys generated for new VMs are stored locally in the script's execution directory. The script attempts to add them to `.gitignore` if committing locally. **Secure these keys and DO NOT commit them manually.** The script attempts to set the private key as a `DEPLOY_SSH_PRIVATE_KEY` secret in GitHub Actions, which is the recommended way for CI/CD pipelines.
*   **LLM Output:** The AI-generated CI/CD pipeline is a **starting point**. Always review it for correctness, security, and efficiency before relying on it.
*   **Resource Costs:** You are responsible for all costs associated with the cloud resources created by this script. Remember to delete resources you no longer need.
*   **Permissions:** The script requires sufficient IAM permissions in your cloud account and repository permissions (write access for commits/secrets) to function correctly.
*   **Deployment Strategy:** The generated CI/CD pipeline focuses on building/testing and providing instructions for *manual* deployment using the SSH key. For fully automated deployment via CI/CD, you MUST ensure the `DEPLOY_SSH_PRIVATE_KEY` secret is correctly configured in your CI/CD provider settings (GitHub Actions, GitLab CI variables, etc.).
*   **Error Handling:** The script includes error handling, but complex cloud or Git configurations might lead to unexpected issues. Check the logs (`-v` flag) for details.
*   **Idempotency:** Resource creation may fail if resources with the specified names already exist. The script allows selecting existing resources to mitigate this partially. Network resource creation (e.g., for Azure/GCP VMs) attempts to be idempotent where possible.

## Output

The script's final output is a set of instructions printed to the console, detailing:

*   The resources created or selected.
*   SSH key details (if generated).
*   Step-by-step instructions for manually accessing VMs via SSH using the appropriate key.
*   Guidance on manual deployment (`scp`, `ssh` commands).
*   Next steps for checking the CI/CD pipeline and cloud resources.

---

*Note: Customize the "Clone the repository" command and any other specific details relevant to your project distribution.*
