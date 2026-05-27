"""
Recompute metrics.reuses for all users (LEDG-1763 follow-up).

The previous count_reuses() implementation used Reuse.visible() which
requires datasets__0__exists=True. That excluded orphan reuses (reuses not
yet linked to any dataset) from the stored metric, causing the admin user
listing to show a lower reuse count than the user profile page (which shows
orphan reuses to admins via visible_by_user).

count_reuses() was corrected to mirror the public listing filter:
    private__ne=True, archived=None, deleted=None
(no datasets__0__exists requirement), but the stored metrics.reuses values
in MongoDB were never back-filled for existing users.

This migration recomputes metrics.reuses for every non-deleted user by
aggregating their qualifying reuses directly in MongoDB and writing the
correct count back into user.metrics.reuses.

The migration is idempotent: re-running it always produces the same result.
"""

import logging

log = logging.getLogger(__name__)


def migrate(db):
    # Aggregate per-owner reuse counts using the same filter as count_reuses().
    pipeline = [
        {
            "$match": {
                "private": {"$ne": True},
                "archived": None,
                "deleted": None,
                "owner": {"$exists": True, "$ne": None},
            }
        },
        {
            "$group": {
                "_id": "$owner",
                "reuse_count": {"$sum": 1},
            }
        },
    ]

    counts: dict = {}
    for doc in db.reuse.aggregate(pipeline):
        if doc["_id"] is not None:
            counts[doc["_id"]] = doc["reuse_count"]

    total_users = 0
    total_updated = 0
    for user_doc in db.user.find({"deleted": None}, {"_id": 1}):
        user_id = user_doc["_id"]
        count = counts.get(user_id, 0)
        result = db.user.update_one(
            {"_id": user_id},
            {"$set": {"metrics.reuses": count}},
        )
        total_users += 1
        if result.modified_count:
            total_updated += 1

    log.info(
        "metrics.reuses recomputed for %d user(s); %d value(s) corrected.",
        total_users,
        total_updated,
    )
