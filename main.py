import os
import random
import shutil
import requests
import argparse
from git import Repo
from github import Github
import re

# === CONFIGURATIONS FROM COMMAND LINE ===
parser = argparse.ArgumentParser(description="LOKI: Automate vulnerability injection and pull request creation.")
parser.add_argument("--llm-endpoint", type=str, required=True,default="http://localhost:1234/v1/chat/completions", help="The endpoint URL for the LLM.")
parser.add_argument("--model-name", type=str, required=True,default="deepseek-coder-v2-lite-instruct", help="The name of the LLM model to use.")
parser.add_argument("--github-token", type=str, required=True,default=os.getenv("GITHUB_TOKEN"), help="The GitHub token for authentication.")
parser.add_argument("--github-org", type=str, required=True, help="The name of the GitHub organization.")
parser.add_argument("--clone-dir", type=str, default="./temp_repo", help="The directory to clone repositories into.")

args = parser.parse_args()

LLM_ENDPOINT = args.llm_endpoint
MODEL_NAME = args.model_name
GITHUB_TOKEN = args.github_token
if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN is required. Set it as an environment variable or pass it as an argument.")
GITHUB_ORG = args.github_org
CLONE_DIR = args.clone_dir


def inject_vulnerabilities_in_files(repo_path, num_vulns=5):
    """
    Injects vulnerabilities into files within a given repository path.

    Args:
        repo_path (Repo): The local repository object.
        num_vulns (int): The number of vulnerabilities to inject.

    Returns:
        list: A list of file paths where vulnerabilities were injected.
    """
    code_extensions = {
        ".py", ".js", ".ts", ".java", ".rb", ".go", ".php", ".c", ".cpp", ".cs",
        ".json", ".toml", ".yaml", ".yml", ".gradle", ".xml", "requirements.txt", "package.json"
    }

    injected_files = []
    vuln_count = 0

    system_prompt = "You are a security AI that injects realistic vulnerabilities into code for testing purposes."

    for root, dirs, files in os.walk(repo_path.working_dir):
        for f in files:
            ext = os.path.splitext(f)[1]
            if ext.lower() in code_extensions or f in code_extensions:
                full_path = os.path.join(root, f)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as file:
                        original_code = file.read()

                    user_prompt = (
                        f"Inject a vulnerability in the following code if possible. "
                        f"Only return the modified code, exactly as it should be written to the file:\n\n{original_code}"
                    )

                    response = requests.post(
                        LLM_ENDPOINT,
                        json={
                            "model": MODEL_NAME,
                            "messages": [
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt}
                            ],
                            "temperature": 0.7,
                            "max_tokens": 8192
                        }
                    )

                    response.raise_for_status()
                    result = response.json()["choices"][0]["message"]["content"].strip()
                    result = re.sub(r"^```[a-zA-Z]*\n", "", result)
                    result = re.sub(r"\n```$", "", result)

                    # Compare the result with the original code
                    if result and result.strip() != original_code.strip():
                        with open(full_path, "w", encoding="utf-8") as f_out:
                            f_out.write(result)
                        injected_files.append(full_path)
                        vuln_count += 1
                        print(f"[LOKI] Vulnerability injected into: {full_path}")

                    if vuln_count >= num_vulns:
                        return injected_files

                except Exception as e:
                    print(f"[LOKI] Error processing {full_path}: {e}")

    return injected_files


def clone_repo(repo_url, clone_dir):
    """
    Clones a repository to a specified directory.

    Args:
        repo_url (str): The URL of the repository to clone.
        clone_dir (str): The directory where the repository will be cloned.

    Returns:
        Repo: The cloned repository object.
    """
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)
    return Repo.clone_from(repo_url, clone_dir)


def create_pull_request(repo, head_branch, base_branch, title, body):
    """
    Creates a pull request in the given repository.

    Args:
        repo (Repository): The GitHub repository object.
        head_branch (str): The name of the branch with changes.
        base_branch (str): The name of the base branch to merge into.
        title (str): The title of the pull request.
        body (str): The body/description of the pull request.

    Returns:
        str: The URL of the created pull request.
    """
    pr = repo.create_pull(
        title=title,
        body=body,
        head=head_branch.name,
        base=base_branch
    )
    return pr.html_url


def main():
    """
    Main function to automate the injection of vulnerabilities into repositories
    and create pull requests for testing purposes.
    """
    num_total = random.randint(1, 10)
    num_code = random.randint(1, min(8, num_total))
    num_deps = num_total - num_code

    print(f"[LOKI] Generating {num_total} vulnerabilities: {num_code} code, {num_deps} dependency\n")

    # Authenticate with GitHub
    gh = Github(GITHUB_TOKEN)
    print("[LOKI] Authenticated with GitHub.")
    gh.get_organization(GITHUB_ORG)
    for repo in gh.get_organization(GITHUB_ORG).get_repos():
        print(f"[LOKI] Repository found: {repo.name}")
        dirc_lone = os.path.join(CLONE_DIR, repo.name)

        repo_local = clone_repo(repo.clone_url, dirc_lone)

        # Check if the repository has a valid HEAD
        if not repo_local.head.is_valid():
            print(f"[LOKI] Repository {repo.name} is empty or has no HEAD configured. Skipping...")
            continue

        # Request injection from LLM
        response = inject_vulnerabilities_in_files(repo_local, num_vulns=5)
        print("[LOKI] LLM responded with vulnerability suggestions.")

        # Generate branch name
        branch_name = f"loki-auto-{random.randint(1000, 9999)}"
        print(f"[LOKI] Generated branch: {branch_name}")
        repo_local.git.fetch()

        # Create new branch
        new_branch = repo_local.create_head(branch_name)
        repo_local.git.checkout(new_branch)

        # Commit & push
        repo_local.git.add(A=True)
        repo_local.index.commit("chore(security): inject vulnerabilities with LOKI")
        origin = repo_local.remote(name='origin')

        # Force push to create the remote branch
        origin.push(refspec=f"{branch_name}:{branch_name}", force=True)
        print(f"[LOKI] Changes pushed to GitHub on branch `{branch_name}`")

        # Create Pull Request
        pr_url = create_pull_request(
            repo,
            new_branch,
            repo.default_branch,
            "Test: LOKI Vulnerability Injection",
            f"Automated injection of {num_code} code vulnerabilities and {num_deps} dependency issues for SAST/SCA testing.\n\nGenerated by LOKI."
        )

        print(f"[LOKI] Pull request created: {pr_url}")


if __name__ == "__main__":
    main()
