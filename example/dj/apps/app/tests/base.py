from django.contrib.auth.models import User


class BaseTestCaseMixin:

    def create_user(self, username='test', email='test@test.cz', password='test', is_active=True):
        return User.objects._create_user(username, email, password, is_active=is_active ,is_staff=True,
                                         is_superuser=True)
