from django.conf import settings
<<<<<<< HEAD
<<<<<<< HEAD
from django.conf.urls import url
=======
=======
>>>>>>> Proversity/staging (#411)
<<<<<<< HEAD
from django.conf.urls import patterns, url
=======
from .views import RecoverPasswordView
>>>>>>> add recover password endpoint
<<<<<<< HEAD
>>>>>>> add recover password endpoint
=======
=======
from .views import RecoverPasswordView
>>>>>>> Proversity/staging (#411)
>>>>>>> Proversity/staging (#411)

from student_account import views

<<<<<<< HEAD
urlpatterns = [
    url(r'^finish_auth$', views.finish_auth, name='finish_auth'),
    url(r'^settings$', views.account_settings, name='account_settings'),
]
=======
if settings.FEATURES.get('ENABLE_COMBINED_LOGIN_REGISTRATION'):
    urlpatterns += patterns(
        'student_account.views',
        url(r'^password$', 'password_change_request_handler', name='password_change_request'),
        url(r'^recover-password$', RecoverPasswordView.as_view({'post': 'post'}), name="restrecover-password"),
    )
>>>>>>> add recover password endpoint

if settings.FEATURES.get('ENABLE_COMBINED_LOGIN_REGISTRATION'):
    urlpatterns += [
        url(r'^password$', views.password_change_request_handler, name='password_change_request'),
    ]
