# LOKI

> **L.O.K.I.** – *Leverage Offensive Knowledge Intelligently*

LOKI is an intelligent offensive testing tool that automatically creates **pull requests** with **realistic vulnerabilities** in source code and dependencies. Designed for testing and benchmarking **SAST (Static Application Security Testing)** and **SCA (Software Composition Analysis)** tools, LOKI uses **AI** to analyze repositories and inject context-aware security flaws that simulate real-world attack patterns.

---

## 🔍 Short Description

LOKI (Leverage Offensive Knowledge Intelligently) is an AI-powered tool that creates pull requests with realistic code and dependency vulnerabilities to test and benchmark SAST/SCA tools.

---

## 🎯 Why LOKI?

Security tools are everywhere—but how effective are they, really?  
LOKI answers this by simulating offensive behavior in a controlled way:

- Creates real-world-like security issues using AI.
- Automates injection of vulnerabilities via pull requests.
- Helps security teams benchmark, train, and improve detection workflows.

LOKI is ideal for:
- Evaluating SAST/SCA tool coverage.
- Simulating adversarial behavior in CI pipelines.
- Security training and education.
- Identifying detection blind spots.

---

## 🚀 Features

- ⚙️ **AI-Powered Vulnerability Generation**
- 🔁 **Automatic Pull Request Creation**
- 🧪 **Injects Both Code & Dependency Flaws**
- 🧠 **Context-Aware Vulnerability Placement**
- 🛠️ **Customizable Payloads and Templates**
- 🧩 **Plugin Support for Custom Vulnerability Types**

---

## 🧠 How It Works

1. **Repository Analysis**  
   Parses project structure, languages, and dependency files.

2. **Vulnerability Planning**  
   Uses AI to decide what and where to inject vulnerabilities.

3. **Injection & Commit**  
   Flaws are inserted, committed, and pushed to a new branch.

4. **Pull Request Creation**  
   A detailed PR is created for use in security testing workflows.

---

## 💣 Examples of Vulnerabilities Introduced

| Type                      | Example                                                                 |
|---------------------------|-------------------------------------------------------------------------|
| Hardcoded Secrets         | AWS keys, database credentials                                          |
| Injection Flaws           | SQL Injection, Command Injection in Flask/Express                      |
| Dependency Vulnerabilities| Use of outdated libraries with known CVEs                              |
| Dangerous Code Use        | `eval()`, `pickle.load()` on user input                                |
| Access Control Bypass     | Missing authorization checks                                            |

---

## 🧰 Tech Stack

- Python 3.10+
- GitHub API
- GitPython, PyYAML
- OpenAI or Local LLMs

---

## 📦 Installation

```bash
git clone https://github.com/your-org/loki.git
cd loki
pip install -r requirements.txt


## 🏃 How to Run

You can run LOKI by providing the required configurations via command-line arguments:

### Example Command

```bash
python [main.py](http://_vscodecontentref_/8) \
  --llm-endpoint "http://localhost:1234/v1/chat/completions" \
  --model-name "deepseek-coder-v2-lite-instruct" \
  --github-token "your_github_token" \
  --github-org "your_github_organization" \
  --clone-dir "./temp_repo"

### Arguments

| Argument         | Description                                      | Required | Default                       |
|-------------------|--------------------------------------------------|----------|-------------------------------|
| `--llm-endpoint`  | The endpoint URL for the LLM.                   | Yes      | N/A                           |
| `--model-name`    | The name of the LLM model to use.               | Yes      | N/A                           |
| `--github-token`  | The GitHub token for authentication.            | Yes      | N/A                           |
| `--github-org`    | The name of the GitHub organization.            | Yes      | N/A                           |
| `--clone-dir`     | The directory to clone repositories into.       | No       | `./temp_repo`                 |
---


## 🛡️ Disclaimer

LOKI is a tool intended strictly for educational, testing, and internal benchmarking purposes.
Only use it in repositories you own or have explicit permission to test.