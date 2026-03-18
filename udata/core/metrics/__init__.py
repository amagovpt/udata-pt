def init_app(app):
    # Load all core metrics
    import udata.core.user.metrics  # noqa
    import udata.core.organization.metrics  # noqa
    import udata.core.discussions.metrics  # noqa
    import udata.core.dataset.metrics  # noqa
    import udata.core.reuse.metrics  # noqa
    import udata.core.followers.metrics  # noqa

    # Connect tracking listeners when enabled
    if app.config.get("TRACKING_ENABLED", True):
        from udata.core.metrics.listeners import connect_listeners

        connect_listeners()
