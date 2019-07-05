""" urls.py """

from django.conf.urls import url, include, patterns
from eox_core import views


urlpatterns = patterns(
    '',
    url(r'^eox-info$', views.info_view),
    url(r'^api/', include('eox_core.api.urls', namespace='eox-api')),
)
