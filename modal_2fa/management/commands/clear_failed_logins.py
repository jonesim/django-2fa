from django.core.management.base import BaseCommand
from django.db.models import Q

from modal_2fa.models import FailedLoginAttempt


class Command(BaseCommand):
    help = 'Deletes records blocking ip addresses or users from logging in'

    def add_arguments(self, parser):
        parser.add_argument("ip_address_or_username")

    def handle(self, *args, **options):
        attempts = FailedLoginAttempt.objects.filter(Q(ip_address=options['ip_address_or_username'])
                                                     | Q(user__username=options['ip_address_or_username']))
        if attempts:
            print(f'Deleting {len(attempts)} record(s)')
            attempts.delete()
        else:
            print('No records found')
