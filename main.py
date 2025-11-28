from fastapi import FastAPI, Request, HTTPException
import hmac
import hashlib
import json
import os
import subprocess
import uvicorn
from dotenv import load_dotenv

_ = load_dotenv()

app = FastAPI()

# Secret for GitHub webhook verification
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

# Local folder where the repo is cloned
LOCAL_DEPLOY_REPO = os.getenv("LOCAL_DEPLOY_REPO")

# Remote repo URL (needed if repo folder is missing)
REMOTE_REPO_URL = os.getenv("REMOTE_REPO_URL")


def verify_signature(request_body: bytes, signature_header: str):
    """Validate GitHub HMAC SHA256 signature."""
    if not signature_header:
        return False
    try:
        sha_name, signature = signature_header.split("=")
    except ValueError:
        return False
    if sha_name != "sha256":
        return False

    mac = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(),
        msg=request_body,
        digestmod=hashlib.sha256,
    )
    expected = mac.hexdigest()
    return hmac.compare_digest(expected, signature)


def pull_repo():
    """Force update local deploy branch to match remote, including submodules, and update Odoo."""
    if not os.path.isdir(LOCAL_DEPLOY_REPO):
        print(f"❌ Directory does not exist: {LOCAL_DEPLOY_REPO}, cloning repo...")
        try:
            subprocess.run(
                ["git", "clone", "--recurse-submodules", "-b", "deploy", REMOTE_REPO_URL, LOCAL_DEPLOY_REPO],
                check=True
            )
            print("✅ Repository cloned successfully")
            return
        except subprocess.CalledProcessError as e:
            print(f"❌ Git clone failed: {e}")
            return

    try:
        print("⬇️ Fetching latest code from remote...")
        subprocess.run(["git", "fetch", "origin"], cwd=LOCAL_DEPLOY_REPO, check=True)

        print("🔄 Resetting local deploy branch to origin/deploy (force)...")
        subprocess.run(["git", "reset", "--hard", "origin/deploy"], cwd=LOCAL_DEPLOY_REPO, check=True)

        print("🔄 Updating submodules...")
        subprocess.run(["git", "submodule", "update", "--init", "--recursive"], cwd=LOCAL_DEPLOY_REPO, check=True)

        print("🐳 Updating Odoo inside Docker (non-interactive)...")
        subprocess.run([
            "docker", "exec", "odoo-odoo-1",
            "odoo", "-d", "odoo",
            "-c", "/etc/odoo/odoo.conf",
            "-u", "all",
            "--stop-after-init",
        ], check=True)

        print("✅ Code, submodules, and Odoo updated successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Git or Docker operation failed: {e}")


@app.post("/webhook/github")
async def github_webhook(request: Request):
    body = await request.body()
    signature_header = request.headers.get("X-Hub-Signature-256")

    if not verify_signature(body, signature_header):
        raise HTTPException(status_code=401, detail="Invalid signature")

    event = request.headers.get("X-GitHub-Event")
    if event != "push":
        return {"message": f"Ignored event: {event}"}

    payload = json.loads(body)
    ref = payload.get("ref")
    if ref != "refs/heads/deploy":
        return {"message": f"Ignored branch: {ref}"}

    commits = payload.get("commits", [])
    pusher = payload.get("pusher", {}).get("name", "unknown")

    print("🚀 Deploy branch push detected!")
    print(f"Pusher: {pusher}")
    for c in commits:
        print(f" - Commit: {c['id'][:7]} — {c['message']}")

    # Force pull latest code including submodules and update Odoo
    pull_repo()

    return {"message": "Webhook processed successfully"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8040, reload=True)
