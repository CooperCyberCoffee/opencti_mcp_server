# Cooper Cyber Coffee OpenCTI MCP Server

## Project Overview
Building an MCP server that bridges Claude Desktop with OpenCTI 6.x for AI-augmented threat intelligence analysis. This addresses the "cyber poverty line" - making threat intelligence accessible to organizations that can't afford $500k enterprise platforms.

Target: $20/month operational cost vs $500k/year enterprise TIPs.

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
