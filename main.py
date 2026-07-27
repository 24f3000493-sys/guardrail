import os
import urllib.parse
from pathlib import Path
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# 1. Define our strict rules
SANDBOX_DIR = Path("/srv/agent-redteam/sandbox-307ced0fcd").resolve()
ALLOWED_HOSTS = {"example.com", "www.iana.org"}

# 2. Automatically create the required files when the server starts
@app.on_event("startup")
async def setup_files():
    # Create the necessary folders
    os.makedirs("/srv/agent-redteam/outside-14c2de60", exist_ok=True)
    os.makedirs("/srv/agent-redteam/sandbox-307ced0fcd/notes", exist_ok=True)
    os.makedirs("/srv/agent-redteam/sandbox-307ced0fcd/encoded", exist_ok=True)

    # Write the specific files required by the grader
    with open("/srv/agent-redteam/outside-14c2de60/canary.txt", "w") as f:
        f.write("AGENT_GUARDRAIL_CANARY_a350704e5b9861948d3f0203412c6e8057e7600d")

    with open("/srv/agent-redteam/sandbox-307ced0fcd/notes/report.txt", "w") as f:
        f.write("SAFE_REPORT_639ce3ab9552086660ef6034")

    with open("/srv/agent-redteam/sandbox-307ced0fcd/notes/looks-like-..-but-safe.txt", "w") as f:
        f.write("SAFE_WEIRD_2de8687e20b1de102c36873b")

    with open("/srv/agent-redteam/sandbox-307ced0fcd/encoded/%2e%2e-literal.txt", "w") as f:
        f.write("SAFE_ENCODED_4de5f7ee5961c2441a77adf4")

# 3. The Guardrail Endpoint (Catch-all route like your last assignment)
@app.api_route("/{path:path}", methods=["GET", "POST"])
async def guardrail(request: Request, path: str):
    # Keep the server alive check
    if request.method == "GET":
        return JSONResponse(content={"status": "Guardrail is active"})

    try:
        body = await request.json()
    except Exception:
        return {"action": "block", "reason": "Invalid JSON", "result": None}

    tool = body.get("tool")
    args = body.get("arguments", {})

    # ----------------------------------------
    # TOOL: READ FILE
    # ----------------------------------------
    if tool == "read_file":
        raw_path = args.get("path", "")
        try:
            # .resolve() is the magic step. It converts fake paths like 
            # "/folder/../folder/secret.txt" into their true absolute path.
            target_path = Path(raw_path).resolve()
            
            # Check if the true path strictly starts with our allowed sandbox folder
            if not str(target_path).startswith(str(SANDBOX_DIR)):
                return {"action": "block", "reason": "Path traversal attempt blocked", "result": None}
            
            if not target_path.is_file():
                return {"action": "block", "reason": "File does not exist", "result": None}

            # If it passes the checks, read the file and allow it
            content = target_path.read_text()
            return {"action": "allow", "reason": "Safe path", "result": content}

        except Exception as e:
            return {"action": "block", "reason": f"Path error: {str(e)}", "result": None}

    # ----------------------------------------
    # TOOL: FETCH URL
    # ----------------------------------------
    elif tool == "fetch_url":
        raw_url = args.get("url", "")
        try:
            # Break the URL down into pieces (scheme, hostname, etc.)
            parsed = urllib.parse.urlparse(raw_url)
            
            if parsed.scheme not in ["http", "https"]:
                return {"action": "block", "reason": "Must use HTTP or HTTPS", "result": None}
            
            # This is the SSRF protection. By strictly forcing the hostname to exactly 
            # match "example.com" or "www.iana.org", attackers cannot use tricks like 
            # example.com@evil.com or 127.0.0.1
            if parsed.hostname not in ALLOWED_HOSTS:
                return {"action": "block", "reason": "Host not in strict allowlist", "result": None}
            
            # Fetch the URL. follow_redirects=False prevents a safe domain from redirecting
            # the server back to an unsafe internal IP address.
            async with httpx.AsyncClient(follow_redirects=False) as client:
                resp = await client.get(raw_url, timeout=5.0)
                
                if 300 <= resp.status_code < 400:
                    return {"action": "block", "reason": "Redirects are unsafe", "result": None}
                
                return {"action": "allow", "reason": "Safe URL", "result": resp.text}

        except Exception as e:
            return {"action": "block", "reason": f"URL error: {str(e)}", "result": None}
    
    # If it's any other tool, block it by default
    return {"action": "block", "reason": "Unknown tool", "result": None}