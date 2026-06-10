#!/usr/bin/env bash
set -euo pipefail

REPO="anomalyco/fastguard"
VERSION="${1:-latest}"

print_banner() {
  cat <<'EOF'
  ⚡ FastGuard - AI-powered security scanner for FastAPI backends
EOF
}

main() {
  print_banner

  # Check for uv, install if missing
  if ! command -v uv &>/dev/null; then
    echo "→ Installing uv (fast Python package installer)..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # Source uv into PATH
    if [ -f "$HOME/.local/bin/env" ]; then
      . "$HOME/.local/bin/env"
    fi
    export PATH="$HOME/.local/bin:$PATH"
  fi

  echo "→ Installing fastguard..."

  if [ "$VERSION" = "latest" ]; then
    uv tool install --python python3 "git+https://github.com/$REPO.git"
  else
    uv tool install --python python3 "git+https://github.com/$REPO.git@$VERSION"
  fi

  echo ""
  echo "  ✓ fastguard installed successfully!"
  echo ""
  echo "  Run:  fastguard --help"
  echo "  Scan: fastguard scan /path/to/your/project"
  echo ""
}

main
