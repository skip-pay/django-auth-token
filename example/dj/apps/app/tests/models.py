from datetime import timedelta

from uuid import uuid4

from django.contrib.auth.hashers import make_password
from django.utils import timezone

from germanium.decorators import data_consumer
from germanium.test_cases.default import GermaniumTestCase
from germanium.tools import assert_equal, assert_true, assert_false, assert_raises, assert_not_equal

from auth_token.models import AuthorizationToken, MobileDevice, MobileDeviceAlreadyExists
from auth_token.config import settings

from .base import BaseTestCaseMixin


__all__ = (
    'TokenTestCase',
)


class TokenTestCase(BaseTestCaseMixin, GermaniumTestCase):

    @data_consumer('create_user')
    def test_should_return_proper_time_to_expiration(self, user):
        expired_token = AuthorizationToken.objects.create(
            user=user, ip='127.0.0.1', backend='test', expires_at=timezone.now()
        )
        expired_token = AuthorizationToken.objects.get(pk=expired_token.pk)
        assert_equal(AuthorizationToken.objects.get(pk=expired_token.pk).time_to_expiration, timedelta(seconds=0))

        non_expired_token = AuthorizationToken.objects.create(user=user, ip='127.0.0.1', backend='test')
        assert_true(non_expired_token.time_to_expiration.total_seconds() > 0)

    @data_consumer('create_user')
    def test_only_one_mobile_device_should_be_primary(self, user):
        mobile_device1 = MobileDevice.objects.activate_or_create(uuid4(), user, is_primary=True)
        mobile_device2 = MobileDevice.objects.activate_or_create(uuid4(), user, is_primary=True)

        assert_false(mobile_device1.refresh_from_db().is_primary)
        assert_true(mobile_device2.refresh_from_db().is_primary)

    def test_only_both_mobile_devices_with_different_users_should_be_primary(self):
        mobile_device1 = MobileDevice.objects.activate_or_create(uuid4(), self.create_user(username='test1'),
                                                                 is_primary=True)
        mobile_device2 = MobileDevice.objects.activate_or_create(uuid4(), self.create_user(username='test2'),
                                                                 is_primary=True)

        assert_true(mobile_device1.refresh_from_db().is_primary)
        assert_true(mobile_device2.refresh_from_db().is_primary)

    @data_consumer('create_user')
    def test_two_active_mobile_devices_with_same_uuid_and_user_should_raise_exception(self, user):
        uuid = uuid4()
        MobileDevice.objects.activate_or_create(uuid, user, is_primary=True)
        with assert_raises(MobileDeviceAlreadyExists):
            MobileDevice.objects.activate_or_create(uuid, user, is_primary=True)

    def test_two_active_mobile_devices_with_same_uuid_should_be_created(self):
        MobileDevice.objects.activate_or_create(uuid4, self.create_user(username='test1'), is_primary=True)
        MobileDevice.objects.activate_or_create(uuid4, self.create_user(username='test2'), is_primary=True)

    @data_consumer('create_user')
    def test_deactivated_mobile_device_should_be_recreated(self, user):
        uuid = uuid4
        mobile_device = MobileDevice.objects.activate_or_create(uuid, user, is_primary=True)
        mobile_device.change_and_save(is_active=False)
        mobile_device = MobileDevice.objects.activate_or_create(uuid, user, is_primary=False, name='test', slug='test')
        assert_true(mobile_device.is_active)
        assert_false(mobile_device.is_primary)
        assert_equal(mobile_device.name, 'test')
        assert_equal(mobile_device.slug, 'test')

    @data_consumer('create_user')
    def test_mobile_device_login_token_should_be_updated_with_check_login_token(self, user):
        mobile_device = MobileDevice.objects.activate_or_create(uuid4, user, is_primary=True)
        mobile_device.change_and_save(login_token=make_password('test', hasher='md5'))
        assert_true(mobile_device.check_login_token('test'))
        assert_true(mobile_device.login_token.startswith('pbkdf2_sha256'))

    @data_consumer('create_user')
    def test_mobile_device_login_token_should_be_updated_with_set_login_token(self, user):
        mobile_device = MobileDevice.objects.activate_or_create(uuid4, user, is_primary=True)
        prev_login_token = mobile_device.login_token
        mobile_device.set_login_token('test')
        assert_not_equal(mobile_device.login_token, prev_login_token)
        assert_true(mobile_device.login_token.startswith('pbkdf2_sha256'))
        assert_true(mobile_device.check_login_token('test'))

    @data_consumer('create_user')
    def test_deactivation_of_mobile_device_should_deactivate_its_authorization_tokens(self, user):
        mobile_device = MobileDevice.objects.activate_or_create(uuid4, user, is_primary=True)
        auth_token = AuthorizationToken.objects.create(
            user=user, ip='127.0.0.1', backend='test', mobile_device=mobile_device
        )

        # make sure everything is active
        assert_true(mobile_device.is_active)
        assert_true(auth_token.refresh_from_db().is_active)

        # deactivating mobile device must deactivate its authorization tokens
        mobile_device.change_and_save(is_active=False)
        assert_false(mobile_device.is_active)
        assert_false(auth_token.refresh_from_db().is_active)

        # activating mobile device must not activate its authorization tokens
        mobile_device.change_and_save(is_active=True)
        assert_true(mobile_device.is_active)
        assert_false(auth_token.refresh_from_db().is_active)
