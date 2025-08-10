# Capture Test Results

Summary of local capture tests using the enhanced fallback strategy:

- Primary: direct tshark capture (may fail due to permissions)
- Fallback: tcpdump + tshark analysis (works reliably with capabilities)
- Optional: sg wireshark group switching (disabled by default; gated by env)

Notes
1. Server restart may be required for changes to take effect
2. The server implementation has been updated with the new fallback strategy
3. Direct testing confirms the strategy works under capability-based setup