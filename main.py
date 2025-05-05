import os
import random
import shutil
import requests
import argparse
from git import Repo
from github import Github
import re
import difflib

# === CONFIGURATIONS FROM COMMAND LINE ===
parser = argparse.ArgumentParser(description="LOKI: Automate vulnerability injection and pull request creation.")
parser.add_argument("--llm-endpoint", type=str, default="http://localhost:1234/v1/chat/completions", help="The endpoint URL for the LLM.")
parser.add_argument("--model-name", type=str,default="deepseek-coder-v2-lite-instruct", help="The name of the LLM model to use.")
parser.add_argument("--github-token", type=str, default=os.getenv("GITHUB_TOKEN"), help="The GitHub token for authentication.")
parser.add_argument("--github-org", type=str, required=True,  help="The name of the GitHub organization.")
parser.add_argument("--clone-dir", type=str, default="./temp_repo", help="The directory to clone repositories into.")

args = parser.parse_args()

LLM_ENDPOINT = args.llm_endpoint
MODEL_NAME = args.model_name
GITHUB_TOKEN = args.github_token
if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN is required. Set it as an environment variable or pass it as an argument.")
GITHUB_ORG = args.github_org
CLONE_DIR = args.clone_dir
import difflib

def count_vulnerability_blocks(original_code, result):
    """
    Counts the number of distinct blocks of lines that were added or modified
    in the result compared to the original code.

    Args:
        original_code (str): The original code as a string.
        result (str): The modified code as a string.

    Returns:
        int: The number of distinct vulnerability blocks.
    """
    diff = difflib.ndiff(original_code.splitlines(), result.splitlines())
    added_or_modified_blocks = 0
    in_block = False

    for line in diff:
        if line.startswith('+ ') and not line.strip() == '+':  # Line added
            if not in_block:
                added_or_modified_blocks += 1
                in_block = True
        elif line.startswith('- ') or line.startswith('  '):  # Line removed or unchanged
            in_block = False

    return added_or_modified_blocks

def inject_vulnerabilities_in_files(repo_path, num_code=5, num_deps=1):
    """
    Injects vulnerabilities into files within a given repository path.

    Args:
        repo_path (Repo): The local repository object.
        num_code (int): The number of code vulnerabilities to inject.
        num_deps (int): The number of dependency vulnerabilities to inject.

    Returns:
        dict: A dictionary with lists of file paths where vulnerabilities were injected.
              Example: {"code": [...], "dependencies": [...]}
    """
    # Separate extensions for code and dependencies
    code_extensions = {".py", ".js", ".ts", ".java", ".rb", ".go", ".php", ".c", ".cpp", ".cs"}
    dependency_files = {"requirements.txt", "package.json", "pom.xml", "build.gradle", "Gemfile"}

    injected_files = {"code": [], "dependencies": []}
    code_vuln_count = 0
    dep_vuln_count = 0

    # Improved prompts for different types of vulnerabilities
    system_prompt_code = (
        "You are a security AI tasked with injecting high-severity vulnerabilities into source code for testing purposes. "
        "Focus on vulnerabilities from the OWASP Top 10, such as SQL Injection, Cross-Site Scripting (XSS), Insecure Deserialization, "
        "and Command Injection. Ensure the injected vulnerabilities are realistic, exploitable, and align with the context of the provided code."
    )
    system_prompt_deps = (
        "You are a security AI tasked with injecting critical vulnerabilities into dependency files for testing purposes. "
        "Focus on introducing outdated or vulnerable library versions with known CVEs, or misconfigurations that could lead to security risks. "
        "Ensure the injected vulnerabilities are relevant to the context of the provided dependency file."
    )

    for root, dirs, files in os.walk(repo_path.working_dir, topdown=True):
        for f in files:
            ext = os.path.splitext(f)[1]
            full_path = os.path.join(root, f)

            # Handle code vulnerabilities
            if ext.lower() in code_extensions and code_vuln_count < num_code:
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as file:
                        original_code = file.read()

                    user_prompt = (
                        f"Inject a high-severity vulnerability in the following code. "
                        f"Focus on OWASP Top 10 vulnerabilities such as SQL Injection, XSS, or Command Injection. "
                        f"Ensure the vulnerability is realistic, exploitable, and aligns with the context of the provided code. "
                        f"Do not rewrite or remove lines unless necessary to introduce the vulnerability:\n\n{original_code}"
                    )

                    response = requests.post(
                        LLM_ENDPOINT,
                        json={
                            "model": MODEL_NAME,
                            "messages": [
                                {"role": "system", "content": system_prompt_code},
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

                    vuln_blocks = count_vulnerability_blocks(original_code, result)
                    if vuln_blocks > 0:
                        with open(full_path, "w", encoding="utf-8") as f_out:
                            f_out.write(result)
                        injected_files["code"].append(full_path)
                        code_vuln_count += 1
                        print(f"[LOKI] Code vulnerability injected into: {full_path}")

                        if code_vuln_count >= num_code and dep_vuln_count >= num_deps:
                            return injected_files

                except Exception as e:
                    print(f"[LOKI] Error processing {full_path}: {e}")

            # Handle dependency vulnerabilities
            if f in dependency_files and dep_vuln_count < num_deps:
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as file:
                        original_deps = file.read()

                    user_prompt = (
                        f"Inject a critical vulnerability in the following dependency file. "
                        f"Focus on introducing outdated or vulnerable library versions with known CVEs, or misconfigurations "
                        f"Do not rewrite or remove lines unless necessary to introduce the vulnerability that could lead to security risks. Ensure the vulnerability is realistic and relevant:\n\n{original_deps}"
                    )

                    response = requests.post(
                        LLM_ENDPOINT,
                        json={
                            "model": MODEL_NAME,
                            "messages": [
                                {"role": "system", "content": system_prompt_deps},
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

                    if result.strip() != original_deps.strip():
                        with open(full_path, "w", encoding="utf-8") as f_out:
                            f_out.write(result)
                        injected_files["dependencies"].append(full_path)
                        dep_vuln_count += 1
                        print(f"[LOKI] Dependency vulnerability injected into: {full_path}")

                        if code_vuln_count >= num_code and dep_vuln_count >= num_deps:
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
    num_total = random.randint(20, 100)  # Increased range for vulnerabilities
    num_code = random.randint(10, min(80, num_total))  # Increased code vulnerabilities
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
        response = inject_vulnerabilities_in_files(repo_local, num_code, num_deps)

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
