# Cooper Cyber Coffee OpenCTI MCP Server

## Project Overview
Building an MCP server that bridges Claude Desktop with OpenCTI 6.x for AI-augmented threat intelligence analysis. This addresses the "cyber poverty line" - making threat intelligence accessible to organizations that can't afford $500k enterprise platforms.

**Current Version:** v0.4.2
**Status:** Production Ready

Target: $20/month operational cost vs $500k/year enterprise TIPs.

## Recent Features (v0.4.2)
- **Multi-Observable Search:** Auto-detects and enriches 6 observable types (IPv4, IPv6, domains, URLs, emails, file hashes)
- **Zero-Knowledge TLP Filtering:** Filtered results indistinguishable from "not found" - no metadata leakage
- **Enhanced Security:** Fixed TLP marking detection, null handling, and strict mode information disclosure

## Previous Features (v0.4.1 and earlier)
- **Progress Reporting:** Real-time status updates for long-running OpenCTI queries via MCP context
- **Operation Cancellation:** User can cancel operations mid-execution with clean abort and audit trail
- **Enhanced Visibility:** Better debugging with progress milestones and operation lifecycle tracking
- **Server-Side TLP Filtering (v0.4.0):** Query-scoped filtering with 40-60% performance improvement (NO hardcoded UUIDs)
- **Rate Limiting (v0.4.0):** Token bucket DoS protection (60 calls/minute default)
- **Enhanced Audit Logging (v0.4.0):** Correlation IDs and SHA256 integrity hashing for tamper detection
- **TLP Filtering (v0.3.0):** CISA-compliant Traffic Light Protocol filtering with configurable policies
- **Air-Gapped Deployment (v0.3.0):** Local LLM support (Llama, Mistral, etc.) for classified environments
- **Data Governance (v0.3.0):** Comprehensive compliance framework (CMMC, NIST 800-171, HIPAA, SOC 2)

## Development Standards
- Python 3.9+ with async/await patterns throughout
- Type hints and Google-style docstrings on everything
- Copyright headers on ALL Python files: "Cooper Cyber Coffee OpenCTI MCP Server\nCopyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee"
- MIT License with Cooper Cyber Coffee branding
- Production-ready code from day one (no TODOs/FIXMEs)

## Architecture Principles
- Simple > Clever (maintainability wins)
- Explicit > Implicit (clarity over magic)
- Tested > Assumed (if untested, it's broken)
- Documented > Self-evident (help future-you)

## Environment Assumptions
- OpenCTI 6.x running (will be at AWS endpoint)
- Python 3.9+ available
- All secrets via environment variables
- OPENCTI_URL, OPENCTI_TOKEN, OPENCTI_SSL_VERIFY

## Quality Bar = Open-Source Ready
Every commit should be:
- No hardcoded credentials
- Comprehensive error handling with helpful messages
- Professional documentation
- Cooper Cyber Coffee branding throughout
- Ready to show on LinkedIn

## Project Mission
Crossing the cyber poverty line - making enterprise-grade threat intelligence accessible to supply chain partners who can't afford traditional platforms.
