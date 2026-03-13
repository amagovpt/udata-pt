#!/usr/bin/env python3
"""
Fix MongoDB text index conflict on the 'user' collection.

MongoDB only allows ONE text index per collection. The old schema had a
'slug_text' index, but the new schema requires a
'last_name_text_first_name_text_email_text' index. This script drops the
old index so the new one can be created automatically by mongoengine.

Usage:
    # Dry-run (default) — shows what would be done, changes nothing
    python scripts/fix_mongo_text_index.py --host 10.55.37.143

    # Apply the fix
    python scripts/fix_mongo_text_index.py --host 10.55.37.143 --apply

    # Custom database name or port
    python scripts/fix_mongo_text_index.py --host 10.55.37.40 --port 27017 --db udata --apply

Environments:
    DEV: --host 10.55.37.143
    TST: --host 10.55.37.40
"""

import argparse
import sys

import pymongo


OLD_INDEX_NAME = "slug_text"
COLLECTION = "user"


def main():
    parser = argparse.ArgumentParser(
        description="Fix MongoDB text index conflict on the 'user' collection."
    )
    parser.add_argument("--host", required=True, help="MongoDB host IP")
    parser.add_argument("--port", type=int, default=27017, help="MongoDB port (default: 27017)")
    parser.add_argument("--db", default="udata", help="Database name (default: udata)")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually drop the index. Without this flag, only shows what would be done.",
    )
    args = parser.parse_args()

    print(f"Connecting to mongodb://{args.host}:{args.port}/{args.db} ...")
    client = pymongo.MongoClient(args.host, args.port, serverSelectionTimeoutMS=5000)

    # Verify connectivity
    try:
        client.admin.command("ping")
    except pymongo.errors.ServerSelectionTimeoutError:
        print(f"ERROR: Cannot connect to MongoDB at {args.host}:{args.port}")
        sys.exit(1)

    db = client[args.db]
    collection = db[COLLECTION]

    # List text indexes
    indexes = collection.index_information()
    text_indexes = {
        name: info
        for name, info in indexes.items()
        if any(field == "text" for _, field in info.get("key", []))
    }

    if not text_indexes:
        print(f"OK: No text indexes found on '{COLLECTION}' collection. Nothing to do.")
        sys.exit(0)

    print(f"\nText indexes found on '{COLLECTION}':")
    for name, info in text_indexes.items():
        weights = info.get("weights", {})
        lang = info.get("default_language", "?")
        print(f"  - {name}  weights={dict(weights)}  language={lang}")

    if OLD_INDEX_NAME not in text_indexes:
        print(f"\nOK: '{OLD_INDEX_NAME}' not found. The correct index may already be in place.")
        sys.exit(0)

    if not args.apply:
        print(f"\n[DRY-RUN] Would drop index '{OLD_INDEX_NAME}'.")
        print("Re-run with --apply to execute.")
        sys.exit(0)

    # Drop the old index
    print(f"\nDropping index '{OLD_INDEX_NAME}' ...")
    collection.drop_index(OLD_INDEX_NAME)
    print("Done. The new text index will be created automatically by mongoengine on next request.")


if __name__ == "__main__":
    main()
