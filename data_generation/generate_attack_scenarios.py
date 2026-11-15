
import csv
import random
from collections import Counter
from pathlib import Path

# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_SEED = 42

PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    PROJECT_ROOT
    / "datasets"
    / "wikimedia"
    / "raw"
    / "cache-t-00.tsv"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "datasets"
    / "synthetic"
)

OUTPUT_FILE = OUTPUT_DIR / "synthetic_attack_scenarios.csv"

# Number of requests generated for EACH scenario.
REQUESTS_PER_SCENARIO = 10_000

# Maximum number of real trace rows used to learn popularity.
MAX_TRACE_ROWS = 200_000

# Fraction of requests affected by each synthetic scenario.
FLASH_CROWD_FRACTION = 0.30
CACHE_POLLUTION_FRACTION = 0.35
DISTRIBUTED_ATTACK_FRACTION = 0.08

# Number of popular objects targeted during a flash crowd.
FLASH_CROWD_OBJECT_COUNT = 10

# Simulated clients for distributed low-rate pollution.
DISTRIBUTED_CLIENT_COUNT = 200

random.seed(RANDOM_SEED)


# ============================================================
# STEP 1: LOAD REAL TRACE AND LEARN OBJECT POPULARITY
# ============================================================

def load_trace():
    """
    Read the Wikimedia TSV trace and learn:
    - Object identifiers
    - Response sizes
    - Observed request frequencies

    This function does not load the entire trace into memory.
    """

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"\nDataset not found:\n{INPUT_FILE}\n\n"
            "Place cache-t-00.tsv in "
            "datasets/wikimedia/raw/."
        )

    object_sizes = {}
    popularity = Counter()
    rows_read = 0

    print("Loading Wikimedia request trace...")
    print(f"Input: {INPUT_FILE}")

    with INPUT_FILE.open(
        "r",
        encoding="utf-8",
        errors="replace",
        newline=""
    ) as file:

        reader = csv.DictReader(file, delimiter="\t")

        required_columns = {
            "relative_unix",
            "hashed_host_path_query",
            "response_size",
            "time_firstbyte",
        }

        if not reader.fieldnames or not required_columns.issubset(
            set(reader.fieldnames)
        ):
            raise ValueError(
                "Unexpected TSV columns. Expected: "
                + ", ".join(sorted(required_columns))
            )

        for row in reader:
            if rows_read >= MAX_TRACE_ROWS:
                break

            try:
                object_id = row["hashed_host_path_query"].strip()
                response_size = int(row["response_size"])

                # Skip malformed or unusable records.
                if not object_id or response_size < 0:
                    continue

                popularity[object_id] += 1

                # Use the first valid observed size for each object.
                if object_id not in object_sizes:
                    object_sizes[object_id] = response_size

                rows_read += 1

            except (ValueError, TypeError, AttributeError):
                continue

    if len(popularity) < 2:
        raise ValueError(
            "Not enough valid objects were found in the trace."
        )

    object_ids = list(popularity.keys())
    weights = [popularity[obj] for obj in object_ids]

    print(f"Valid trace requests read: {rows_read:,}")
    print(f"Unique objects found: {len(object_ids):,}")

    return object_ids, weights, object_sizes


# ============================================================
# STEP 2: HELPER FUNCTIONS
# ============================================================

def weighted_real_object(object_ids, weights):
    """
    Sample an object according to its observed popularity.
    Frequently requested real objects are more likely to appear.
    """

    return random.choices(
        object_ids,
        weights=weights,
        k=1
    )[0]


def create_request(
    scenario,
    request_number,
    content_id,
    response_size,
    client_id,
    event_type,
    is_attack,
):
    """
    Create one standardized request record.
    """

    return {
        "scenario": scenario,
        "request_id": request_number,
        "timestamp": request_number,
        "content_id": content_id,
        "response_size": response_size,
        "client_id": client_id,
        "event_type": event_type,
        "is_attack": int(is_attack),
    }


def synthetic_object_id(scenario, request_number):
    """
    Give synthetic objects a unique namespace so they cannot
    accidentally collide with real hashed object identifiers.
    """

    return f"SYNTH_{scenario.upper()}_{request_number:08d}"


def normal_request(
    scenario,
    request_number,
    object_ids,
    weights,
    object_sizes,
    client_id=None,
):
    content_id = weighted_real_object(object_ids, weights)

    if client_id is None:
        client_id = f"client_{random.randint(1, 500):04d}"

    return create_request(
        scenario=scenario,
        request_number=request_number,
        content_id=content_id,
        response_size=object_sizes[content_id],
        client_id=client_id,
        event_type="normal",
        is_attack=False,
    )


# ============================================================
# SCENARIO 1: NORMAL TRAFFIC
# ============================================================

def generate_normal(object_ids, weights, object_sizes):
    scenario = "normal"
    records = []

    for i in range(REQUESTS_PER_SCENARIO):
        records.append(
            normal_request(
                scenario,
                i,
                object_ids,
                weights,
                object_sizes,
            )
        )

    return records


# ============================================================
# SCENARIO 2: LEGITIMATE FLASH CROWD
# ============================================================

def generate_flash_crowd(object_ids, weights, object_sizes):
    """
    A flash crowd increases requests for popular content.

    IMPORTANT:
    Flash-crowd requests are legitimate and is_attack = 0.
    """

    scenario = "flash_crowd"
    records = []

    popular_objects = sorted(
        zip(object_ids, weights),
        key=lambda item: item[1],
        reverse=True,
    )[:FLASH_CROWD_OBJECT_COUNT]

    flash_ids = [item[0] for item in popular_objects]
    flash_weights = [item[1] for item in popular_objects]

    burst_start = int(REQUESTS_PER_SCENARIO * 0.35)
    burst_end = int(
        burst_start
        + REQUESTS_PER_SCENARIO * FLASH_CROWD_FRACTION
    )

    for i in range(REQUESTS_PER_SCENARIO):
        if burst_start <= i < burst_end:
            # Genuine sudden demand for already popular content.
            content_id = random.choices(
                flash_ids,
                weights=flash_weights,
                k=1,
            )[0]

            event_type = "legitimate_flash_crowd"

            client_id = f"flash_client_{random.randint(1, 1000):04d}"

            records.append(
                create_request(
                    scenario,
                    i,
                    content_id,
                    object_sizes[content_id],
                    client_id,
                    event_type,
                    False,
                )
            )
        else:
            records.append(
                normal_request(
                    scenario,
                    i,
                    object_ids,
                    weights,
                    object_sizes,
                )
            )

    return records


# ============================================================
# SCENARIO 3: CACHE POLLUTION
# ============================================================

def generate_cache_pollution(
    object_ids,
    weights,
    object_sizes,
):
    """
    Generate a mixture of normal requests and pollution requests.

    Pollution requests mostly target unique, previously unseen
    synthetic objects, increasing cache occupancy and evictions.
    """

    scenario = "cache_pollution"
    records = []

    attack_count = int(
        REQUESTS_PER_SCENARIO * CACHE_POLLUTION_FRACTION
    )

    attack_positions = set(
        random.sample(
            range(REQUESTS_PER_SCENARIO),
            attack_count,
        )
    )

    for i in range(REQUESTS_PER_SCENARIO):
        if i in attack_positions:
            content_id = synthetic_object_id(scenario, i)

            # Synthetic sizes are intentionally varied.
            response_size = random.randint(4_000, 150_000)

            records.append(
                create_request(
                    scenario,
                    i,
                    content_id,
                    response_size,
                    f"polluter_{random.randint(1, 30):03d}",
                    "cache_pollution",
                    True,
                )
            )
        else:
            records.append(
                normal_request(
                    scenario,
                    i,
                    object_ids,
                    weights,
                    object_sizes,
                )
            )

    return records


# ============================================================
# SCENARIO 4: DISTRIBUTED LOW-RATE POLLUTION
# ============================================================

def generate_distributed_low_rate(
    object_ids,
    weights,
    object_sizes,
):
    """
    Spread pollution requests across many simulated clients.

    The total malicious fraction is low, and attack requests
    are distributed across the full request timeline.
    """

    scenario = "distributed_low_rate"
    records = []

    attack_count = int(
        REQUESTS_PER_SCENARIO * DISTRIBUTED_ATTACK_FRACTION
    )

    attack_positions = set(
        random.sample(
            range(REQUESTS_PER_SCENARIO),
            attack_count,
        )
    )

    for i in range(REQUESTS_PER_SCENARIO):
        if i in attack_positions:
            content_id = synthetic_object_id(scenario, i)

            response_size = random.randint(4_000, 100_000)

            client_number = random.randint(
                1,
                DISTRIBUTED_CLIENT_COUNT,
            )

            records.append(
                create_request(
                    scenario,
                    i,
                    content_id,
                    response_size,
                    f"distributed_client_{client_number:03d}",
                    "distributed_low_rate_pollution",
                    True,
                )
            )
        else:
            records.append(
                normal_request(
                    scenario,
                    i,
                    object_ids,
                    weights,
                    object_sizes,
                )
            )

    return records


# ============================================================
# STEP 3: GENERATE AND SAVE LABELLED DATA
# ============================================================

def save_records(records):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "scenario",
        "request_id",
        "timestamp",
        "content_id",
        "response_size",
        "client_id",
        "event_type",
        "is_attack",
    ]

    # Write incrementally to avoid holding all scenarios in memory.
    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()

        for record in records:
            writer.writerow(record)


def main():
    object_ids, weights, object_sizes = load_trace()

    print("\nGenerating scenarios...")

    generators = [
        ("normal", generate_normal),
        ("flash_crowd", generate_flash_crowd),
        ("cache_pollution", generate_cache_pollution),
        ("distributed_low_rate", generate_distributed_low_rate),
    ]

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "scenario",
        "request_id",
        "timestamp",
        "content_id",
        "response_size",
        "client_id",
        "event_type",
        "is_attack",
    ]

    total_records = 0

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()

        for scenario_name, generator in generators:
            records = generator(
                object_ids,
                weights,
                object_sizes,
            )

            writer.writerows(records)
            total_records += len(records)

            attack_count = sum(
                record["is_attack"] for record in records
            )

            print(
                f"{scenario_name}: "
                f"{len(records):,} requests, "
                f"{attack_count:,} labelled attack requests"
            )

            del records

    print("\nGeneration complete.")
    print(f"Total requests: {total_records:,}")
    print(f"Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
