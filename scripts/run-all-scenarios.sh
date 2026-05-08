#!/bin/bash
set -e

SCENARIOS_FILE="scripts/scenarios.json"
RECOVERY_MIN=3
DURATION_PER_SCENARIO=1  # dakika

# Postgres'e scenario insert helper
insert_scenario() {
  local id="$1"
  local desc="$2"
  local started="$3"
  docker compose exec -T postgres psql -U research -d ddos_research -c "
    INSERT INTO \"Scenario\" (id, name, description, \"startedAt\", \"endedAt\")
    VALUES ('$id', '$id', '$desc', '$started', NULL)
    ON CONFLICT (id) DO UPDATE SET \"startedAt\" = EXCLUDED.\"startedAt\";
  "
}

end_scenario() {
  local id="$1"
  local ended="$2"
  docker compose exec -T postgres psql -U research -d ddos_research -c "
    UPDATE \"Scenario\" SET \"endedAt\"='$ended' WHERE id='$id';
  "
}

run_scenario() {
  local id="$1"
  local k6_scripts="$2"      # comma-separated
  local slowhttp_modes="$3"  # comma-separated
  local duration_min="$4"

  echo "==================================================="
  echo "Scenario: $id (${duration_min} min)"
  echo "==================================================="

  local started=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  insert_scenario "$id" "$id scenario" "$started"

  local pids=()

  # k6 scripts (background)
  IFS=',' read -ra K6_ARR <<< "$k6_scripts"
  for script in "${K6_ARR[@]}"; do
    [ -z "$script" ] && continue
    echo "  Starting k6 $script..."
    SCENARIO_ID="$id" \
      k6 run --duration "${duration_min}m" \
        --env "BASE_URL=http://localhost:8080" \
        --env "SCENARIO_ID=$id" \
        "k6/scenarios/$script.js" \
        > "logs/${id}_${script}.log" 2>&1 &
    pids+=($!)
  done

  # slowhttptest modes (background)
  if [ -n "$slowhttp_modes" ]; then
    IFS=',' read -ra SLOW_ARR <<< "$slowhttp_modes"
    for mode in "${SLOW_ARR[@]}"; do
      [ -z "$mode" ] && continue
      echo "  Starting slowhttp $mode..."
      ./scripts/run-slowhttp.sh "$mode" $((duration_min * 60)) \
        > "logs/${id}_${mode}.log" 2>&1 &
      pids+=($!)
    done
  fi

  # Hepsinin bitmesini bekle
  for pid in "${pids[@]}"; do
    wait "$pid" || echo "  Process $pid exited with non-zero"
  done

  local ended=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  end_scenario "$id" "$ended"

  echo "  Scenario ended. Recovery period (${RECOVERY_MIN} min legit-only)..."
  SCENARIO_ID="${id}_recovery" \
    k6 run --duration "${RECOVERY_MIN}m" \
      --env "BASE_URL=http://localhost:8080" \
      --env "SCENARIO_ID=${id}_recovery" \
      "k6/scenarios/01_legitimate_only.js" \
      > "logs/${id}_recovery.log" 2>&1
}

mkdir -p logs

# Sırayla çalıştır
run_scenario "S1_legit_only"           "01_legitimate_only" ""                    "$DURATION_PER_SCENARIO"
run_scenario "S2_http_flood"           "01_legitimate_only,02_http_flood" ""      "$DURATION_PER_SCENARIO"
run_scenario "S3_low_rate_bot"         "01_legitimate_only,03_low_rate_bot" ""    "$DURATION_PER_SCENARIO"
run_scenario "S4_credential_stuffing"  "01_legitimate_only,04_credential_stuffing" "" "$DURATION_PER_SCENARIO"
run_scenario "S5_mimicry_flood"        "01_legitimate_only,05_mimicry_flood" ""   "$DURATION_PER_SCENARIO"
run_scenario "S6_slowloris"            "01_legitimate_only" "slowloris,slow_post" "$DURATION_PER_SCENARIO"

echo "All scenarios completed."
