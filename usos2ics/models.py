from django.contrib import admin
from django.db import models
from django.core.urlresolvers import reverse


class USOSAuthenticatedUser(models.Model):
    alias = models.CharField(max_length=20, unique=True)
    access_token_key = models.CharField(max_length=20)
    access_token_secret = models.CharField(max_length=40)

    def get_absolute_url(self):
        return reverse('calendar_link', args=(self.alias,))

admin.site.register(USOSAuthenticatedUser)
