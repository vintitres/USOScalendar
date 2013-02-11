from django_ical.views import ICalFeed
import datetime
import json
#import oauth2 as oauth


#def get_consumer():
    #return oauth.Consumer(CONSUMER_KEY, CONSUMER_SECRET)


#def get_user_token():
        #client = oauth.Client(get_consumer())
        #resp, content = client.request(request_token_url, "GET")
        #if resp['status'] != '200':
            #raise Exception("Invalid response %s:\n%s" % (resp['status'],
            #content))
        #def _read_token(content):
            #arr = dict(urlparse.parse_qsl(content))
                #return oauth.Token(arr['oauth_token'],
                #arr['oauth_token_secret'])
        #request_token = _read_token(content)
# Python
import oauth2 as oauth
import cgi

# Django
from django.shortcuts import get_object_or_404
from django.http import HttpResponseRedirect
from django.conf import settings
from django.views.generic import RedirectView, CreateView, View
from django.forms import ModelForm, RegexField

from models import USOSAuthenticatedUser


consumer = oauth.Consumer(settings.USOS_CONSUMER_KEY,
                          settings.USOS_CONSUMER_SECRET)
client = oauth.Client(consumer)

request_token_url = settings.USOS_API_URL + \
    'services/oauth/request_token?scopes=studies|offline_access&' + \
    'oauth_callback=http://students.mimuw.edu.pl:1236/login/authenticated/'
authorize_url = settings.USOS_API_URL + 'services/oauth/authorize'
access_token_url = settings.USOS_API_URL + 'services/oauth/access_token'
user_activities_url = settings.USOS_API_URL + 'services/tt/user'


def oauth_token_from_content(content):
    parsed = dict(cgi.parse_qsl(content))
    return oauth.Token(parsed['oauth_token'], parsed['oauth_token_secret'])


class USOSLoginView(RedirectView):
    permanent = False

    def get_redirect_url(self, **kwargs):
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
            fields = ['alias']
            widgets = {
                'name': RegexField(regex=r'[a-zA-Z0-9]+'),
            }
    form_class = USOSAuthenticatedUserForm
    model = USOSAuthenticatedUser

    def get(self, request, *args, **kwargs):
        if not 'access_token' in request.session:
            oauth_verifier = self.request.GET.get('oauth_verifier')
            request_token = self.request.session['request_token']
            request_token.set_verifier(oauth_verifier)
            client = oauth.Client(consumer, request_token)
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
        return u'USOSCalendar of %s' % obj.alias

    def link(self, obj):
        return obj.get_absolute_url()

    def description(self, obj):
        return u'USOSCalendar of %s' % obj.alias

    def items(self, u):
        access_token = oauth.Token(u.access_token_key, u.access_token_secret)
        client = oauth.Client(consumer, access_token)
        resp, content = client.request(
            user_activities_url +
            '?start=' + str(datetime.datetime.now().date()) +
            '&fields=type|start_time|end_time|name|url|room_number' +
            '&days=7',
            "GET")
        if resp['status'] != '200':
            raise Exception(u"Invalid response %s.\n%s" % (
                resp['status'],
                content)
            )
        return json.loads(content)

    def item_title(self, item):
        print self.timezone
        return item['name']['pl']

    def item_location(self, item):
        if item['type'] == 'classgroup':
            return item['room_number']
        elif item['type'] == 'classgroup2':
            return item['room_number']
        return '?'

    def item_start_datetime(self, item):
        print item['start_time']
        return datetime.datetime.strptime(item['start_time'],
                                          '%Y-%m-%d %H:%M:%S')

    def item_end_datetime(self, item):
        return datetime.datetime.strptime(item['end_time'],
                                          '%Y-%m-%d %H:%M:%S')

    def item_link(self, item):
        return item['url'] or ''

    def item_description(self, item):
        return item['url'] or ''


class USOSCalendarLinkView(View):
    def get(self, request, *args, **kwargs):
        return HttpResponseRedirect(
            'http://www.google.com/calendar/render?cid=%s' % (
                'http://%s:%s/calendar/%s/events.ics' % (
                    request.META['SERVER_ADDR'],
                    request.META['SERVER_PORT'],
                    kwargs['alias'],
                ),
            )
        )


#class USOSCalendar(View):
    #def get(self, request, *args, **kwargs):
        #access_token = self.request.session['access_token']
        #client = oauth.Client(consumer, access_token)
        #resp, content = client.request(user_activities_url + "?start=" +
            #str(datetime.datetime.now().date()) + "&days=3", "GET")
        #if resp['status'] != '200':
            #raise Exception(
                #u"Invalid response %s.\n%s" % (resp['status'], content))
        #items = json.loads(content)
        ## Print today's activities.
        #activities = sorted(items, lambda x, y: cmp(x['start_time'],
                                                     #y['start_time']))
        #feed = feedgenerator.ICal20Feed(
            #title=u'USOSCalendar',
            #link=u"http://www.example.com/events.ical",
            #description=u"A iCalendar feed of my events.",
            #language=u"en",
        #)
        #for item in activities:
            #feed.add_item(
                #title=item['name']['en'],
                #link=u"http://www.example.com/test/",
                #description="Testing."
                #start_datetime=datetime(item['start_time']),
                #end_datetime=datetime(item['end_time']),
            #)
        #return HttpResponse(ret)
