#!/usr/bin/env bash
# Launch Factorio with our hook .so injected via LD_PRELOAD.
#
# Usage:
#   ./scripts/run_factorio.sh [factorio args...]
#
# Looks for libfactorio_hooks.so under mods/native/build/.

set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mod_dir=$(cd "$script_dir/.." && pwd)
toolkit_root=$(cd "$mod_dir/../.." && pwd)
workspace=$(cd "$toolkit_root/.." && pwd)

so="$mod_dir/build/libfactorio_hooks.so"
if [ ! -f "$so" ]; then
  echo "build the hook .so first:" >&2
  echo "  cmake -S $mod_dir -B $mod_dir/build && cmake --build $mod_dir/build -j" >&2
  exit 1
fi

# Default: <workspace>/factorio/bin/x64/factorio. Override with FACTORIO_EXE=...
exe="${FACTORIO_EXE:-$workspace/factorio/bin/x64/factorio}"
if [ ! -x "$exe" ]; then
  echo "factorio binary not found at $exe" >&2
  exit 1
fi

# LD_PRELOAD only takes effect for the immediate child. We pass it via env
# so it survives Factorio's exec inside Steam wrappers if any.
echo "running: LD_PRELOAD=$so $exe $*"
exec env LD_PRELOAD="$so" "$exe" "$@"
