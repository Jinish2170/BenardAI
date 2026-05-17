# examples/

Drop sample files here to scan from the CLI or dashboard. **Do not commit binaries** —
this directory is gitignored except for this README.

## Safe sample sources

- **Benign PE for smoke-testing**: copy any small binary you own (e.g. `notepad.exe`
  from `C:\Windows\System32` on Windows). Bernard should classify it as `benign`
  or `inconclusive` (low signals + no intel hits).

- **EICAR test file** (harmless but every AV flags it):
  Note: Windows Defender will quarantine this on touch. Either disable real-time
  scanning for this directory, or test EICAR from a controlled VM.

  ```
  X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
  ```

- **MalwareBazaar samples** (real malware — require an `ABUSECH_API_KEY`):
  Browse https://bazaar.abuse.ch/browse/ and look up hashes via the dashboard
  instead of downloading the binary itself.

## Hash-only triage

You can fully analyze a sample by hash without ever touching the binary:

```bash
bernard scan --value 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

Bernard will query VirusTotal + MalwareBazaar + ThreatFox and synthesize a verdict.
