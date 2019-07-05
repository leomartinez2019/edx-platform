# -*- coding: utf-8 -*-
"""The generic views for the exc-core plugin project"""

from __future__ import unicode_literals

import json
from os.path import dirname, realpath
from subprocess import check_output, CalledProcessError

from django.http import HttpResponse
from django.utils import six


import eox_core


def info_view(request):
    """
    Basic view to show the working version and the exact git commit of the
    installed app
    """
    response_data = {
        "version": eox_core.__version__,
        "name": "eox-core",
    }
    return HttpResponse(
        json.dumps(response_data),
        content_type="application/json"
    )
