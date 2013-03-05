import datetime
import random
import string
from datetime import timedelta
import json
import cgi

from django.shortcuts import get_object_or_404
from django.http import HttpResponseRedirect
from django.conf import settings
from django.views.generic import RedirectView, CreateView, View
from django.forms import ModelForm, RegexField
from django.core.urlresolvers import reverse

from django_ical.views import ICalFeed
import oauth2 as oauth
import certifi

from models import USOSAuthenticatedUser


authorize_url = settings.USOS_API_URL + 'services/oauth/authorize'
user_activities_url = settings.USOS_API_URL + 'services/tt/user'
request_token_url_without_callback = (
        '%sservices/oauth/request_token?scopes=studies|offline_access&'
        'oauth_callback=') % settings.USOS_API_URL


def usos_get_consumer():
    return oauth.Consumer(settings.USOS_CONSUMER_KEY,
                          settings.USOS_CONSUMER_SECRET)


def oauth_token_from_content(content):
    parsed = dict(cgi.parse_qsl(content))
    return oauth.Token(parsed['oauth_token'], parsed['oauth_token_secret'])


class USOSLoginView(RedirectView):
    permanent = False

    def get_redirect_url(self, **kwargs):
        client = oauth.Client(usos_get_consumer())
        client.ca_certs = certifi.where()
        request_token_url = '%shttp://%s%s' % (
                    request_token_url_without_callback,
                    self.request.META['HTTP_HOST'],
                    reverse('user_authenticated'),
                )
        resp, content = client.request(request_token_url, 'GET')
        if resp['status'] != '200':
            raise Exception('Invalid response from USOS: "%s"' % content)
        request_token = oauth_token_from_content(content)
        self.request.session['request_token'] = request_token
        return '%s?oauth_token=%s' % (authorize_url, request_token.key)


class USOSAuthenticatedView(CreateView):
    class USOSAuthenticatedUserForm(ModelForm):
        class Meta:
            model = USOSAuthenticatedUser
            fields = ['name', 'alias']
            #widgets = {
                #'name': RegexField(regex=r'[a-zA-Z0-9]+'),
            #}
    form_class = USOSAuthenticatedUserForm
    model = USOSAuthenticatedUser

    def get(self, request, *args, **kwargs):
        if not 'access_token' in request.session:
            oauth_verifier = self.request.GET.get('oauth_verifier')
            request_token = self.request.session['request_token']
            request_token.set_verifier(oauth_verifier)
            client = oauth.Client(usos_get_consumer(), request_token)
            client.ca_certs = certifi.where()
            access_token_url = (settings.USOS_API_URL +
                                'services/oauth/access_token')
            resp, content = client.request(access_token_url, "GET")
            if resp['status'] != '200':
                raise Exception('Invalid response from USOS: "%s"' % content)
            access_token = oauth_token_from_content(content)
            request.session['access_token'] = access_token
        return super(USOSAuthenticatedView, self).get(request, *args, **kwargs)

    def form_valid(self, form):
        access_token = self.request.session['access_token']
        form.instance.access_token_key = access_token.key
        form.instance.access_token_secret = access_token.secret
        return super(USOSAuthenticatedView, self).form_valid(form)


class USOSCalendar(ICalFeed):
    product_id = '-//example.com//Example//PL'
    timezone = 'Europe/Warsaw'

    def get_object(self, request, alias):
        return get_object_or_404(USOSAuthenticatedUser, alias=alias)

    def title(self, obj):
        return u'%s' % obj.name

    def link(self, obj):
        return obj.get_absolute_url()

    def description(self, obj):
        return u'USOSCalendar: %s' % obj.name

    def items(self, u):
        access_token = oauth.Token(u.access_token_key, u.access_token_secret)
        client = oauth.Client(usos_get_consumer(), access_token)
        client.ca_certs = certifi.where()
        ret = []
        for i in range(-2, 23):
            resp, content = client.request(
                user_activities_url +
                '?start=' +
                str(datetime.datetime.now().date() + timedelta(days=(7 * i))) +
                '&fields=' +
                'type|start_time|end_time|name|url|room_number|unit_id' +
                '&days=7',
                "GET")
            if resp['status'] != '200':
                raise Exception(u"Invalid response %s.\n%s" % (
                    resp['status'],
                    content)
                )
            ret.extend(json.loads(content))
        return ret

    def item_guid(self, item):
        return '%s%s%s%s' % (
            item['unit_id'],
            item['start_time'],
            item['end_time'],
            ''.join(
                random.choice(string.ascii_uppercase + string.digits)
                    for x in range(10)),
        )

    def item_title(self, item):
        return item['name']['pl']

    def item_location(self, item):
        if item['type'] == 'classgroup' or item['type'] == 'classgroup2':
            return item['room_number']
        return '?'

    def item_start_datetime(self, item):
        return datetime.datetime.strptime(item['start_time'],
                                          '%Y-%m-%d %H:%M:%S')

    def item_end_datetime(self, item):
        return datetime.datetime.strptime(item['end_time'],
                                          '%Y-%m-%d %H:%M:%S')

    def item_link(self, item):
        return item['url'] or ''

    def item_description(self, item):
        return ''


class USOSCalendarLinkView(View):
    def get(self, request, *args, **kwargs):
        return HttpResponseRedirect(
            'http://www.google.com/calendar/render?cid=%s' % (
                'http://%s%s' % (
                    request.META['HTTP_HOST'],
                    reverse('get_calendar', args=(kwargs['alias'],)),
                ),
            )
        )
