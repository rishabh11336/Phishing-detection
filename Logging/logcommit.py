import os
import datetime
import requests


def get_changed_files(directory):
    # Retrieve list of changed log files
    changed_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".log"):  # Assuming only log files are logged
                changed_files.append(os.path.join(root, file))
    return changed_files


def to_github(
    repo_owner,
    repo_name,
    branch_name,
    github_token,
    commit_message,
    files,
    log_directory,
):
    if not files:
        print("No files have changed. Skipping commit.")
        return

    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/git/refs/heads/{branch_name}"
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
    }

    # Get the latest commit SHA for the branch
    response = requests.get(url, headers=headers)
    response_json = response.json()

    # Check if 'object' key exists in the response
    if "object" not in response_json:
        print("Error: 'object' key not found in response.")
        return

    latest_commit_sha = response_json["object"]["sha"]

    # Create a new tree with the updated files
    tree_data = {
        "base_tree": latest_commit_sha,
        "tree": [
            {
                "path": file_path.split("/")[-1],  # Only take the filename
                "mode": "100644",
                "content": open(file_path, "r").read(),
            }
            for file_path in files
        ],
    }
    response = requests.post(
        f"https://api.github.com/repos/{repo_owner}/{repo_name}/git/trees",
        json=tree_data,
        headers=headers,
    )
    tree_sha = response.json()["sha"]
    commit_data = {
        "message": commit_message,
        "parents": [latest_commit_sha],
        "tree": tree_sha,
    }
    response = requests.post(
        f"https://api.github.com/repos/{repo_owner}/{repo_name}/git/commits",
        json=commit_data,
        headers=headers,
    )
    commit_sha = response.json()["sha"]

    # Update the branch reference to the new commit
    ref_data = {"sha": commit_sha}
    response = requests.patch(url, json=ref_data, headers=headers)


def commit_to_github(commit_message):
    log_directory = "./"
    repo_owner = "rishabh11336"
    repo_name = "Log-Phishing-Detection"
    branch_name = "main"
    from dotenv import load_dotenv

    load_dotenv()
    github_token = os.environ("GITHUB_TOKEN")

    files = get_changed_files(log_directory)

    to_github(
        repo_owner,
        repo_name,
        branch_name,
        github_token,
        commit_message,
        files,
        log_directory,
    )