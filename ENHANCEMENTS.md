# ENHANCEMENTS — Sharon-Needles/nuclei Fork

This fork of [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) adds a custom template directory for social engineering surface detection. No Go source files were modified — all additions are purely additive.

---

## What Was Added

### `nuclei-social-templates/` — Custom SE Detection Templates

Three YAML templates targeting the social engineering attack surface that upstream nuclei-templates does not address:

---

### 1. `social-email-spoof-check.yaml`

**What it catches**: Domains that are trivially spoofable via email — the primary entry point for phishing campaigns.

**Detection logic**:
- SPF record is missing entirely → any mail server can send as this domain
- SPF record contains `+all` (pass-all) → explicitly allows any sender
- DMARC record is missing from `_dmarc.<domain>` → no enforcement, no reporting
- DMARC record has `p=none` → monitor-only mode, no rejection of spoofed mail

**Protocol**: DNS (TXT record queries)

**Example run**:
```bash
# Against a domain list
nuclei -l domains.txt -t nuclei-social-templates/social-email-spoof-check.yaml -silent

# Single domain
echo "target.com" | nuclei -t nuclei-social-templates/social-email-spoof-check.yaml
```

**Example finding**:
```
[social-email-spoof-check:no-dmarc-record] [dns] [medium] target.com
[social-email-spoof-check:spf-pass-all] [dns] [medium] weakspf.com
```

---

### 2. `social-open-redirect-params.yaml`

**What it catches**: Open redirect vulnerabilities via common query parameter names. Allows phishing URLs like `https://trusted.com/?next=https://evil.com` that appear legitimate to victims.

**Detection logic**:
Injects an external canary URL into 12 common redirect parameters:
`next`, `redirect`, `redirect_to`, `redirect_url`, `return`, `return_to`, `url`, `goto`, `dest`, `destination`, `target`, `redir`

Flags when:
- Response `Location` header redirects to the injected URL (3xx open redirect)
- Response body reflects the injected URL (JS-based redirect)

**Protocol**: HTTP (GET, redirect-following disabled)

**Example run**:
```bash
nuclei -l urls.txt -t nuclei-social-templates/social-open-redirect-params.yaml -silent
```

**Example finding**:
```
[social-open-redirect-params:redirect-location] [http] [medium] https://target.com/?next=https://canary.Sharon-Needles.redir.test
```

**Note**: Replace the canary domain with a domain you control (e.g., a Burp Collaborator or interactsh URL) for confirmed out-of-band validation. The default canary domain is non-resolving by design.

---

### 3. `social-clickjacking-check.yaml`

**What it catches**: Login pages missing both `X-Frame-Options` and `frame-ancestors` CSP — vulnerable to UI redressing / clickjacking attacks that steal credentials.

**Detection logic** (all three conditions must be true):
1. Response body contains `<input type="password">` — confirms this is a login/sensitive form
2. `X-Frame-Options` header is absent from the response
3. `Content-Security-Policy` does not include a `frame-ancestors` directive

The password-field requirement eliminates noise from non-sensitive pages.

**Protocol**: HTTP (GET)

**Example run**:
```bash
nuclei -l urls.txt -t nuclei-social-templates/social-clickjacking-check.yaml -silent
```

**Example finding**:
```
[social-clickjacking-check] [http] [medium] https://target.com/login
```

---

## Running All Custom Templates Together

```bash
# Scan a URL list with all three SE templates
nuclei -l urls.txt -t nuclei-social-templates/ -silent

# With JSON output for piping into other tools
nuclei -l urls.txt -t nuclei-social-templates/ -json -silent | jq '.info.name, .matched-at'

# Combine with upstream tags
nuclei -l urls.txt -t nuclei-social-templates/ -tags takeovers -silent

# Verbose mode to debug template matching
nuclei -l urls.txt -t nuclei-social-templates/ -v
```

---

## Integration with social.sh

These templates map directly to phases in `social.sh` (Sharon-Needles/social):

| Phase | social.sh Phase | Template |
|-------|----------------|----------|
| 2 | DNS/Email Security | `social-email-spoof-check.yaml` |
| 3 | Clickjacking Detection | `social-clickjacking-check.yaml` |
| 5 | Open Redirect | `social-open-redirect-params.yaml` |
| 9 | Subdomain Takeover | upstream `takeovers/` tag |

social.sh can call these with:
```bash
nuclei -l "$TARGETS" -t "$NUCLEI_TEMPLATES/nuclei-social-templates/" -silent -json >> "$OUTPUT/nuclei_se_findings.json"
```

---

## Build

No changes to Go source — build is identical to upstream:

```bash
go build ./cmd/nuclei/
# or
make build
```

Version: v3.8.0 (upstream base, unmodified)
