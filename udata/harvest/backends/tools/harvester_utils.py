# -*- coding: utf-8 -*-
import logging
from datetime import datetime
from udata.i18n import lazy_gettext as _

from flask import current_app, render_template
from flask_mail import Message
import re

#from udata import theme
# from udata_front import theme
from udata.models import (
    Dataset, User, Role
)

log = logging.getLogger(__name__)

'''
Checks for missing datasets in source
'''
def missing_datasets_warning(job_items, source):

    job_datasets = [item.dataset.id for item in job_items]

    domain_harvested_datasets = Dataset.objects(__raw__={
        'extras.harvest:domain': source.domain,
        'private': False,
        'deleted': None
    }).all()
    
    missing_datasets = []
    for dataset in domain_harvested_datasets:
        if dataset.id not in job_datasets:
            dataset.private = True
            missing_datasets.append(dataset)
            dataset.save()
    
    if missing_datasets:
        org_recipients = [ member.user.email for member in source.organization.members if member.role == 'admin' ]
        admin_role = Role.objects.filter(name='admin').first()
        recipients = [ user.email for user in User.objects.filter(roles=admin_role).all() ]

        #recipients = list(set(org_recipients + recipients))

        subject = 'Relatório harvesting dados.gov - {}.'.format(source)

        context = {
            'subject': subject,
            'harvester': source,
            'datasets': missing_datasets,
            'server': current_app.config.get('SERVER_NAME')
        }

        msg = Message(subject=subject, sender='dados@ama.pt', recipients=org_recipients, cc=['dados@ama.pt'], bcc=recipients)
        msg.body = theme.render('mail/harvester_warning.txt', **context)
        msg.html = theme.render('mail/harvester_warning.html', **context)

        mail = current_app.extensions.get('mail')
        try:
            mail.send(msg)
        except:
            pass

def normalize_url_slashes(url: str) -> str:
    """
    Replace all backslashes in a URL with forward slashes.
    Remove any accidental multiple slashes after the protocol.
    """
    if not url:
        return url
    # Substitui todos os tipos de backslash por slash
    url = url.replace("\\", "/")
    # Separa protocolo do resto
    parts = url.split("://", 1)
    if len(parts) == 2:
        # Remove múltiplos slashes seguidos no caminho (mas não no protocolo)
        parts[1] = re.sub(r'/+', '/', parts[1])
        return "://".join(parts)
    else:
        return re.sub(r'/+', '/', url)