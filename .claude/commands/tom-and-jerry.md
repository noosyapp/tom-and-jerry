---
description: Launch an authorized Tom & Jerry security scan against a target frontend, in Docker.
argument-hint: "[port | host:port | URL]  e.g. 3000"
---

Run an authorized Tom & Jerry dynamic security scan.

Requested target: `$ARGUMENTS`

The scan is black-box (it only reaches the app over the network), but the follow-up fix step edits
source code and uses the **current working directory as the target repository**. So this command is
meant to be run with the session rooted in the scanned app's repo. The working directory is detected
automatically — nothing to configure.

Follow these steps exactly:

1. Resolve `$ARGUMENTS` into a full target URL:
   - **Bare port** (just digits, e.g. `3000`): use the machine's LAN IPv4 so the app is reached
     as a real network client would. Detect it with `ipconfig getifaddr en0`, falling back to
     `ipconfig getifaddr en1`. If both are empty, use `host.docker.internal` and say so. The URL
     is `http://<ip-or-host>:<port>`.
   - **`host:port`** or a URL with a scheme: use it as given (add `http://` if the scheme is
     missing). If the host is `localhost` or `127.0.0.1`, replace it with `host.docker.internal`
     so the container can reach an app on the host.
   - **Empty**: use `TJ_FRONTEND_URL` from `.env`, falling back to `http://host.docker.internal:3000`.
2. Derive the hostname from that URL. **That hostname is the only in-scope host for this run** —
   never scan anything else.
3. Confirm `.env` exists and has a non-empty `ANTHROPIC_API_KEY`. If not, stop and tell the user
   to create it from `.env.example` and set the key.
4. Run the scan in Docker, streaming its output (`--build` keeps the image in sync with the
   current source):
   `docker compose run --rm --build --name tom-and-jerry tom-and-jerry pnpm dev -- --frontend=<URL> --scope=<HOST>`
5. When it finishes, open the newest `reports/<runId>/report.md` and summarize the confirmed
   findings (id, severity, title) plus the report path. If there were none, say so plainly.
6. If there were confirmed findings, point the user to the remediation plan at
   `reports/<runId>/remediation.md` and offer to apply the fixes by running `/tom-and-jerry-fix`
   with that file's path. Do not start editing code or commit anything here — remediation is its
   own step, runs in the target repo, and never commits without the user's go-ahead.
