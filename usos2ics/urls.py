from django.conf.urls import patterns, url
from views import USOSLoginView, USOSAuthenticatedView, \
    USOSCalendar, USOSCalendarLinkView


urlpatterns = patterns(
    '',

    url(r'^login/?$', USOSLoginView.as_view()),
    url(r'^login/authenticated/?$', USOSAuthenticatedView.as_view(),
        name='user_authenticated'),
    url(r'^calendar/(?P<alias>[-\w]+)/events.ics$', USOSCalendar(),
        name='get_calendar'),
    url(r'^calendar/(?P<alias>[-\w]+)/$', USOSCalendarLinkView.as_view(),
        name='calendar_link'),
)
