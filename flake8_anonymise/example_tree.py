import ast
from pprint import pprint

tree = ast.parse("""
from django.db import models
from django.utils.translation import gettext_lazy as _
from django_nova_users.models import User
from rules.contrib.models import RulesModelBase, RulesModelMixin


class Account(RulesModelMixin, models.Model, metaclass=RulesModelBase):

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='account',
    )
    photo = models.ImageField(
        _('аватар'),
        upload_to='media',
        blank=True,
        null=True,
    )
    birth_date = models.DateField(
        _('дата рождения'),  
        blank=True,  
        null=True,
    )
    passport_series = models.CharField(
        _('серия паспорта'),
        max_length=4,
        blank=True,
    )
    passport_number = models.CharField(
        _('номер паспорта'),
        max_length=4,
        blank=True,
    )

    class Meta(object):
        verbose_name = _('аккаунт')
        verbose_name_plural = ('аккаунты')

    def str(self):
        return self.user.full_name
""")

pprint(ast.dump(tree))
