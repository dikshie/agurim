#!/bin/sh
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

echo "=================================================="
echo "Running Agurim Test Suite"
echo "=================================================="

# 1. Build C programs
echo "[Test 1/8] Compiling src/ (agurim, aguri3)..."
(cd src && make clean && make) > /dev/null
echo "  -> src/ compiled successfully."

echo "[Test 2/8] Compiling src/aguri3_xflow/ (aguri3_xflow)..."
(cd src/aguri3_xflow && make clean && make) > /dev/null
echo "  -> aguri3_xflow compiled successfully."

# 2. Test agurim reaggregation
echo "[Test 3/8] Testing agurim re-aggregation..."
OUT_TXT=$(./src/agurim tests/fixtures/sample.agr)
echo "${OUT_TXT}" | grep -q "192.0.2.1"
echo "${OUT_TXT}" | grep -q "82500000 bytes"
echo "  -> Re-aggregation output verified."

# 3. Test agurim JSON plotting output
echo "[Test 4/8] Testing agurim JSON plotting output..."
OUT_JSON=$(./src/agurim -p -i 300 tests/fixtures/sample.agr)
echo "${OUT_JSON}" | python3 -m json.tool > /dev/null
echo "${OUT_JSON}" | grep -q '"criteria": "byte"'
echo "  -> JSON format verified."

# 4. Test Protocol view and filters
echo "[Test 5/8] Testing agurim protocol view (-P) and filtering (-f)..."
OUT_PROTO=$(./src/agurim -p -P -i 300 tests/fixtures/sample.agr)
echo "${OUT_PROTO}" | grep -q "6:443:52123"

OUT_FILTER=$(./src/agurim -f "192.0.2.1 198.51.100.1" tests/fixtures/sample.agr)
echo "${OUT_FILTER}" | grep -q "192.0.2.1"
if echo "${OUT_FILTER}" | grep -q "192.0.2.2"; then
    echo "Filter test failed: unselected IP 192.0.2.2 found in output!" >&2
    exit 1
fi
echo "  -> Protocol view and filter options verified."

# 5. Test Python 3 CGI scripts, linting and dev server
echo "[Test 6/8] Testing Python 3 compilation, linting, and CGI scripts..."
python3 -m py_compile cgi-bin/*.py cgi-bin/*.cgi scripts/*.py agurim_agent/*.py agurim_agent/agents/*.py
if command -v ruff >/dev/null 2>&1; then
    ruff check . cgi-bin/*.cgi
elif command -v uv >/dev/null 2>&1; then
    uv run ruff check . cgi-bin/*.cgi
fi
CGI_OUT=$(QUERY_STRING="outfmt=json&criteria=byte" python3 cgi-bin/myagurim.cgi)
echo "${CGI_OUT}" | grep -q "Content-Type: application/json"
TEST_CGI_OUT=$(python3 cgi-bin/test.cgi)
echo "${TEST_CGI_OUT}" | grep -q "Hello Agurim!"
echo "  -> Python 3 scripts verified."

# 6. Test scripts/reaggregate.sh
echo "[Test 7/8] Testing scripts/reaggregate.sh..."
sh scripts/reaggregate.sh -v -t 2026103115 -d /nonexistent_test_dir 2>&1 | grep -q "log dir: /nonexistent_test_dir does not exist"
echo "  -> Shell scripts verified."

# 7. Test Google ADK Multi-Agent team suite
echo "[Test 8/8] Testing Google ADK Multi-Agent System (agents, tools, sentinel)..."
if command -v uv >/dev/null 2>&1; then
    uv run python -m unittest tests/test_multiagent_team.py
else
    python3 -m unittest tests/test_multiagent_team.py
fi
echo "  -> Google ADK Multi-Agent System verified."

echo "=================================================="
echo "All tests passed successfully!"
echo "=================================================="
