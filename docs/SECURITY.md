# Molt-Shield Security

## Security Model

Molt-Shield implements a **zero-trust** security model assuming that:
- The network is always hostile
- The container may be compromised
- Data must be protected at all layers

## Threat Model

### Protected Against
- IP leakage via numeric values
- Proprietary tag name exposure
- Structural pattern analysis
- External network exfiltration

### Not Protected Against
- Semantic inference from patterns
- Timing attacks on transformations
- Side-channel attacks
- Memory forensics (without encryption)

## Security Layers

### 1. Network Isolation

**Requirement:** Server binds to localhost only (127.0.0.1 or ::1)

```yaml
# docker-compose.prod.yml
environment:
  - MOLT_HOST=127.0.0.1
```

**Verification:**
```python
from src.security import verify_network_isolation
issues = verify_network_isolation()
```

### 2. Filesystem Permissions

**Requirements:**
- Input directory mounted read-only
- Output directory writable by container
- Vault in tmpfs or encrypted volume

```yaml
# docker-compose.prod.yml
volumes:
  - prod_input:/home/appuser/data/input:ro    # Read-only
  - prod_output:/home/appuser/data/output      # Writable
  - prod_vault:/home/appuser/vault:rw         # Writable tmpfs
```

### 3. Process Security

**Requirements:**
- Container runs as non-root (UID > 0)
- no-new-privileges flag set
- No dangerous capabilities

```yaml
# docker-compose.prod.yml
security_opt:
  - no-new-privileges:true
user: "1000:1000"
```

### 4. Data Masking

**Transformations applied:**
- All numeric values → `VAL_<uuid>` placeholders
- Proprietary tags → generic shadow names
- Element order → randomized (deterministic with seed)

## Security Verification

### Pre-Deployment Checklist

- [ ] MCP server binds to 127.0.0.1 only
- [ ] No outbound network connectivity
- [ ] MOLT_STRICT=true enforced
- [ ] Input volume read-only
- [ ] Vault in encrypted tmpfs
- [ ] Container runs as non-root
- [ ] no-new-privileges:true set
- [ ] No dangerous capabilities
- [ ] No numeric values in output
- [ ] No proprietary tag names exposed

### Running Security Checks

```bash
# Inside container
python -c "from src.security import run_security_checks; passed, issues = run_security_checks(); print(passed, issues)"

# Or via CLI (if strict mode enabled)
MOLT_STRICT=true python -m src.server
```

### Security Tests

```bash
# Run security test suite
python -m pytest tests/security/ -v
```

## Environment Variables

| Variable | Default | Security Impact |
|----------|---------|-----------------|
| MOLT_HOST | 127.0.0.1 | Must be localhost in strict mode |
| MOLT_STRICT | false | Enables all security checks |
| MOLT_INPUT_DIR | ./data/input | Must be read-only |
| MOLT_VAULT_DIR | ./vault | Should be tmpfs |

## Limitations

### Obfuscation ≠ Encryption

Molt-Shield anonymizes data but does not encrypt it. The output is readable by anyone with access to the sanitized XML.

### Semantic Leakage

Patterns in the data may still reveal information:
- Relative magnitudes (larger/smaller)
- Correlations between elements
- Structural relationships

### Vault Security

Vault files contain original values and must be:
- Stored securely (encrypted at rest)
- Never committed to version control
- Protected from unauthorized access

## Best Practices

1. **Review policies** - Always audit auto-generated policies before use
2. **Use strict mode** - Enable MOLT_STRICT in production
3. **Network isolation** - Ensure no external connectivity
4. **Regular audits** - Run security tests in CI/CD
5. **Vault management** - Rotate vault files regularly

## Incident Response

If you suspect a security incident:

1. **Isolate** - Disconnect from network immediately
2. **Preserve** - Save vault and logs for investigation
3. **Analyze** - Check for leaked data patterns
4. **Remediate** - Update policies, regenerate vaults
5. **Report** - Document the incident

## Compliance

Molt-Shield can help with:
- Data minimization requirements
- IP protection in AI interactions
- Audit trails via vault storage
- Separation of concerns (data/AI)
