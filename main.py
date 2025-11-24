#!/usr/bin/env python3
"""
Cooper Cyber Coffee OpenCTI MCP Server - Main Entry Point
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

Contact: matt@coopercybercoffee.com
"""

import asyncio
import sys
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from opencti_mcp.server import OpenCTIMCPServer
from opencti_mcp.utils import setup_logging, load_config, get_version_info


def print_banner():
    """Print startup banner with Cooper Cyber Coffee branding to stderr."""
    version_info = get_version_info()
    banner = f"""
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║          Cooper Cyber Coffee OpenCTI MCP Server                       ║
║                                                                       ║
║  Version: {version_info['version']:<58} ║
║  OpenCTI: {version_info['opencti_version_required']:<58} ║
║                                                                       ║
║  Built by: Matthew Hopkins / Cooper Cyber Coffee                     ║
║  License: MIT                                                         ║
║                                                                       ║
║  Enterprise-grade threat intelligence for Claude Desktop             ║
║  Making AI-enhanced security accessible to everyone                  ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝

🔗 Project: https://coopercybercoffee.com
📧 Contact: {version_info['contact']}

Starting MCP server...
"""
    print(banner, file=sys.stderr)


async def main():
    """Main entry point for the MCP server."""
    try:
        # Print startup banner
        print_banner()

        # Load configuration
        print("📋 Loading configuration from environment...", file=sys.stderr)
        config = load_config()
        print(f"✅ Configuration loaded", file=sys.stderr)
        print(f"   OpenCTI URL: {config['opencti_url']}", file=sys.stderr)
        print(f"   Log Level: {config['log_level']}", file=sys.stderr)
        print(file=sys.stderr)

        # Setup logging
        logger = setup_logging(config['log_level'])
        logger.info(
            "startup",
            version=get_version_info()['version'],
            opencti_url=config['opencti_url']
        )

        # Create and run server
        print("🚀 Initializing OpenCTI MCP Server...", file=sys.stderr)
        server = OpenCTIMCPServer(config)

        print("✅ Server initialized", file=sys.stderr)
        print("📡 Connecting to OpenCTI...", file=sys.stderr)
        print(file=sys.stderr)
        print("=" * 75, file=sys.stderr)
        print("MCP Server is now running!", file=sys.stderr)
        print("Connect Claude Desktop to start querying threat intelligence", file=sys.stderr)
        print("=" * 75, file=sys.stderr)
        print(file=sys.stderr)

        # Run the server
        await server.run()

    except KeyboardInterrupt:
        print("\n\n⚠️  Shutdown requested by user", file=sys.stderr)
        print("👋 Cooper Cyber Coffee OpenCTI MCP Server stopped", file=sys.stderr)
        sys.exit(0)

    except ValueError as e:
        print(f"\n❌ Configuration Error: {e}", file=sys.stderr)
        print("\n📝 Setup Instructions:", file=sys.stderr)
        print("1. Copy .env.example to .env", file=sys.stderr)
        print("2. Set OPENCTI_URL to your OpenCTI instance URL", file=sys.stderr)
        print("3. Set OPENCTI_TOKEN from OpenCTI Settings > API Access", file=sys.stderr)
        print("4. Run the server again", file=sys.stderr)
        print(f"\n💡 See README.md for detailed setup instructions", file=sys.stderr)
        sys.exit(1)

    except ConnectionError as e:
        print(f"\n❌ Connection Error: {e}", file=sys.stderr)
        print("\n🔧 Troubleshooting:", file=sys.stderr)
        print("1. Verify OpenCTI is running and accessible", file=sys.stderr)
        print("2. Check OPENCTI_URL is correct in .env", file=sys.stderr)
        print("3. Verify network connectivity to OpenCTI", file=sys.stderr)
        print("4. Check firewall settings", file=sys.stderr)
        print("5. Review OpenCTI logs for errors", file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        print(f"\n❌ Unexpected Error: {e}", file=sys.stderr)
        print(f"\n📧 For support, contact: {get_version_info()['contact']}", file=sys.stderr)
        print(f"🐛 Report issues: https://github.com/CooperCyberCoffee/opencti-mcp-server/issues", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    """Entry point when run as a script."""
    # Ensure we're using Python 3.9+
    if sys.version_info < (3, 9):
        print("❌ Error: Python 3.9 or higher is required", file=sys.stderr)
        print(f"   Current version: {sys.version}", file=sys.stderr)
        print("\n📥 Install Python 3.9+:", file=sys.stderr)
        print("   - macOS: brew install python@3.9", file=sys.stderr)
        print("   - Ubuntu: sudo apt install python3.9", file=sys.stderr)
        print("   - Windows: Download from python.org", file=sys.stderr)
        sys.exit(1)

    # Run the async main function
    asyncio.run(main())
