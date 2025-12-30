TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
COMMIT=$(git rev-parse --short HEAD)

OUTDIR="results/${COMMIT}_${TIMESTAMP}"
mkdir -p "$OUTDIR"

echo "Saving benchmark results to $OUTDIR"

# set up variables
PORT=8080
LOCAL_DNS="127.0.0.1 -p $PORT"
PUBLIC_DNS="1.1.1.1"

# check if DNS server is running
if ! lsof -iUDP:$PORT >/dev/null 2>&1; then
    echo "WARNING: UDP port $PORT is not running on 127.0.0.1. Make sure to start the local DNS server before running benchmarks." >&2
    exit 1
fi

# grab tests from the --tests cmd line arg
TESTS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tests)
            IFS=',' read -r -a TESTS <<< "$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Use default if --tests was not provided
DEFAULT_TESTS=("uncached" "cached" "parallel")
if [[ ${#TESTS[@]} -eq 0 ]]; then
    TESTS=("${DEFAULT_TESTS[@]}")
fi

for test in "${TESTS[@]}"; do
    echo "\nRunning test: $test\n"

    if ! [[ -x "$test.sh" ]]; then
        echo "Invalid test $test: file does not exist or is not executable; skipping."
        continue
    fi

    RESULTS_FILE="$OUTDIR/${test}_results.json"
    hyperfine \
     --warmup 1 \
     --export-json $RESULTS_FILE \
     --parameter-list server "$LOCAL_DNS","$PUBLIC_DNS" \
      "SERVER='{server}' ./$test.sh" 2> /dev/null # we are suppressing warnings
done
