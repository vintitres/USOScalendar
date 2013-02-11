from django.conf.urls import patterns, include, url
from django.contrib import admin
from usos2ics.views import USOSLoginView, USOSAuthenticatedView, \
    USOSCalendar, USOSCalendarLinkView

admin.autodiscover()

urlpatterns = patterns(
    '',
    url(r'^login/?$', USOSLoginView.as_view()),
    url(r'^login/authenticated/?$', USOSAuthenticatedView.as_view(),
        name='user_authenticated'),
    url(r'^calendar/(?P<alias>\w+)/events.ics$', USOSCalendar(),
        name='get_calendar'),
    url(r'^calendar/(?P<alias>\w+)/$', USOSCalendarLinkView.as_view(),
        name='calendar_link'),

    url(r'^admin/', include(admin.site.urls)),
)
