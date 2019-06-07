"""
This module contains signals needed for LLPA special needings
"""
import json
from datetime import datetime

from django.dispatch import receiver

from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
from openedx.core.djangoapps.user_api.preferences.api import set_user_preference
from student.views import REGISTER_USER

ACCEPT_TOS_DESITION_TEXT = "accept"


@receiver(REGISTER_USER)
def add_tos_acceptance_preference_for_new_user(
    sender,
    user,
    registration,
    **kwargs
):  # pylint: disable=unused-argument
    """
    Called after user created and saved

    Args:
        sender: Not used
        user: The user object for which tos acceptance preference will be created
        registration: Not used
        kwargs: Not used
    """
    options_modal = configuration_helpers.get_value("TOS_ACCEPTANCE", {})
    modal_enforcement = options_modal.get("modal_enforcement", False)

    # If modal enforcement is not enabled, just return
    if not modal_enforcement:
        return

    # Proceed to accept the current version of the tos
    name_preference_tos = options_modal.get("tos_name_preference", "")
    tos_version = options_modal.get("tos_version", "")
    date_today = datetime.today().strftime('%Y-%m-%dT%H:%M:%S%z')
    value_preference = {
        "tos_version": tos_version,
        "date": date_today,
        "decision": ACCEPT_TOS_DESITION_TEXT
    }
    set_user_preference(user, name_preference_tos, json.dumps(value_preference))
