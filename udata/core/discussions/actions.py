from udata.models import Dataset, Reuse

from .models import Discussion


def discussions_for(user, only_open=True):
    """
    Build a queryset to query discussions related to a given user's assets.

    It includes discussions coming from the user's organizations

    :param bool only_open: whether to include closed discussions or not.
    """
    # Only fetch required fields for discussion filtering (id and slug)
    # Greatly improve performances and memory usage
    datasets = Dataset.objects.owned_by(user.id, *user.organizations).only("id", "slug")
    reuses = Reuse.objects.owned_by(user.id, *user.organizations).only("id", "slug")

    # TODO: add dataservices when ready. It would now break notification routing in current admin
    # since dataservices aren't supported by the current admin.
    # dataservices = Dataservice.objects.owned_by(user.id, *user.organizations).only("id", "slug")

    qs = Discussion.objects(subject__in=list(datasets) + list(reuses))
    if only_open:
        qs = qs(closed__exists=False)
    return qs


def delete_discussions_for_subject(subject):
    """
    Delete every discussion attached to a subject, one document at a time.

    `Discussion.objects(subject=...).delete()` happens to do the same today: a
    `QuerySet.delete()` falls back to per-document deletes as long as *some* mongoengine
    `pre_delete`/`post_delete` receiver is registered for the model. Two unrelated
    modules register one for `Discussion` -- `udata.core.reports`, because it is in
    `REPORTABLE_MODELS`, and `udata.search`, because it has a search adapter -- and
    neither has anything to do with notifications. Deleting explicitly means
    `on_discussion_deleted`, and the notification cleanup listening to it, no longer
    rides on either of them staying put.
    """
    for discussion in Discussion.objects(subject=subject):
        discussion.delete()
