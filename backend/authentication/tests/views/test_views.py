from unittest.mock import Mock, MagicMock, patch
from urllib import parse
from parameterized import parameterized

import pytest
from rest_framework.test import APITestCase
from django.test import override_settings
from django.urls import reverse
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from authentication.factories import UserFactory, StaffUserFactory, SuperuserFactory
from authentication.models import User
from authentication.serializers import UserSerializer
from authentication.views import MIN_SEARCH_LENGTH, MAX_SEARCH_RESULTS
from shared import frontend_urls
from .utils import assert_unauthenticated

pytestmark = [pytest.mark.django_db]

USER_EMAIL = "user@test.com"
VALID_PASSWORD = "test_password123"
INVALID_PASSWORD = "wrong_password123"
TEST_TOKEN = "test_token"
TEST_CAPTCHA_KEY = "test_captcha_key"

USER_DATA = {
    "email": USER_EMAIL,
    "password": VALID_PASSWORD,
}

REGISTER_USER_DATA = {
    **USER_DATA,
    "captchaKey": TEST_CAPTCHA_KEY,
}

GOOGLE_USER_DATA = {
    "email": USER_EMAIL,
    "token": TEST_TOKEN,
    "provider": User.PROVIDER_GOOGLE,
}

FACEBOOK_USER_DATA = {
    **GOOGLE_USER_DATA,
    "provider": User.PROVIDER_FACEBOOK,
}

SUCCESSFUL_FACEBOOK_RESPONSE = Mock(
    json=lambda: {"access_token": "test_access_token", "email": USER_EMAIL}, ok=True
)
FAILED_FACEBOOK_RESPONSE = Mock(json=lambda: {"error": "bad_token"}, ok=False)


class TestLogin:
    def test_login(self, authenticate_and_test):
        UserFactory(**USER_DATA)
        authenticate_and_test("authentication:login", USER_DATA)

    def test_login_wrong_password(self, authenticate_and_test):
        UserFactory(**USER_DATA)
        data = {
            **USER_DATA,
            "password": INVALID_PASSWORD,
        }
        authenticate_and_test("authentication:login", data, success=False)


class TestRegister:
    @pytest.mark.parametrize(
        "password",
        [
            "test_password",  # No number
            "837493938481",  # No letter
            "password1",  # Too common
            "uam38m2",  # Too short
        ],
    )
    def test_register_with_bad_password(self, authenticate_and_test, password):
        data = {
            **REGISTER_USER_DATA,
            "password": password,
        }
        authenticate_and_test("authentication:register", data, success=False)

    def test_register_with_bad_email(self, authenticate_and_test):
        data = {
            **REGISTER_USER_DATA,
            "email": "abc@abc",
        }
        authenticate_and_test("authentication:register", data, success=False)

    def test_register_with_blank_captcha_key(self, authenticate_and_test):
        data = {
            **REGISTER_USER_DATA,
            "captchaKey": "",
        }
        authenticate_and_test("authentication:register", data, success=False)

    def test_register_with_bad_captcha_key(self, authenticate_and_test):
        data = {
            **REGISTER_USER_DATA,
            # Already validated captcha key which cannot be re-used.
            "captchaKey": "03AGdBq25VLxRmMS6CO5AHCocz-CC46Npovoj_EsU8-q11F-C9MyjPP-bwzZ_WJgjVIGmmPwN6IRS4OACv6f7sKdPxCYDpHtcfnsynpjiBT0uqNQMy_xnJDEYRPt6aYLKgSnwcE1QiN2NwIue7BpDh4zSLVQYTm-T4IgdAPciDC_nakAdvkw8jh4Ph1nArZdSkrFDPi_x_wzVSpHin_hLF79nped-tlZuTiIVsxxjq1PRD1BJgUOhmTkdwYRHqeMOdlp4Vkdk-NVi1lpbTDXS9fCt94ztRQcCC85qND9AKwV0-bH9NcLtkYvJ5ZR5gJtB4Om4YZZAizPDIexQ8uv3hNA0nDo-P6uEumYcAwj7025DFN6uAvArb3kQGv98QYovYTa-xmb8PSB0mSOtDPNyOThizWoAKio9RwkyEA3Y9V58s7acTWd-OLKBT1pK7yc8ibt21miX4ARLd",
        }
        authenticate_and_test("authentication:register", data, success=False)

    def test_register_without_captcha_key(self, authenticate_and_test):
        data = {
            **USER_DATA,
        }
        authenticate_and_test("authentication:register", data, success=False)

    def test_register_existing_email(self, authenticate_and_test):
        UserFactory(**USER_DATA)
        data = {**REGISTER_USER_DATA, "password": INVALID_PASSWORD}
        authenticate_and_test("authentication:register", data, success=False)

    @patch("authentication.serializers.check_captcha_key", new=MagicMock(return_value=True))
    def test_redirect(self, authenticate_and_test):
        redirect_url = "http://localhost:1234/test_path"
        data = {
            **REGISTER_USER_DATA,
            "next": redirect_url,
        }
        authenticate_and_test("authentication:register", data, redirect_url=redirect_url)

    @patch("authentication.serializers.check_captcha_key", new=MagicMock(return_value=True))
    @override_settings(VALID_REDIRECT_HOSTNAMES=["*.testing.com"])
    def test_redirect_wildcard(self, authenticate_and_test):
        redirect_url = "http://sub.testing.com"
        data = {
            **REGISTER_USER_DATA,
            "next": redirect_url,
        }
        authenticate_and_test("authentication:register", data, redirect_url=redirect_url)

    @patch("authentication.serializers.check_captcha_key", new=MagicMock(return_value=True))
    def test_ignores_bad_redirect_param(self, authenticate_and_test):
        data = {
            **REGISTER_USER_DATA,
            "next": "https://badsite.com",
        }
        authenticate_and_test("authentication:register", data)


@patch("authentication.serializers.check_captcha_key", new=MagicMock(return_value=True))
class TestLogout:
    def test_logout(self, client, authenticate_and_test):
        authenticate_and_test("authentication:register", REGISTER_USER_DATA)
        response = client.get(reverse("logout"))

        assert response.status_code == 302
        assert response.url == frontend_urls.LOGIN
        assert_unauthenticated(client)

    def test_unauthenticated_logout(self, client):
        response = client.get(reverse("logout"))

        assert response.status_code == 302
        assert response.url == frontend_urls.LOGIN
        assert_unauthenticated(client)

    def test_logout_preserves_query_params(self, client, authenticate_and_test):
        authenticate_and_test("authentication:register", REGISTER_USER_DATA)
        query_params = {"test": "value"}
        response = client.get(reverse("logout"), query_params)

        assert response.status_code == 302

        parsed_url = parse.urlparse(response.url)
        assert parsed_url.path == frontend_urls.LOGIN

        query_string = parse.urlencode(query_params)
        assert parsed_url.query == query_string

        assert_unauthenticated(client)

    @override_settings(VALID_REDIRECT_HOSTNAMES=["*.testing.com"])
    def test_logout_redirects_to_logout_redirect(self, client, authenticate_and_test):
        authenticate_and_test("authentication:register", REGISTER_USER_DATA)
        test_url = "https://www.testing.com"
        params = {"logoutNext": test_url}
        response = client.get(reverse("logout"), params)

        assert response.status_code == 302
        assert response.url == test_url
        assert_unauthenticated(client)

    @override_settings(VALID_REDIRECT_HOSTNAMES=["*.testing.com"])
    def test_logout_does_not_redirect_to_bad_domain(self, client, authenticate_and_test):
        authenticate_and_test("authentication:register", REGISTER_USER_DATA)
        params = {"logoutNext": "https://www.badsite.com"}
        response = client.get(reverse("logout"), params)

        assert response.status_code == 302
        parsed_url = parse.urlparse(response.url)
        assert parsed_url.path == frontend_urls.LOGIN
        assert_unauthenticated(client)

    def test_logout_blacklists_user_tokens(self, client, authenticate_and_test):
        authenticate_and_test("authentication:register", REGISTER_USER_DATA)
        user = User.objects.get(email=USER_DATA["email"])
        user_token = str(RefreshToken.for_user(user))
        client.get(reverse("logout"))
        with pytest.raises(TokenError):
            RefreshToken(user_token)


class TestListCreateUsersView(APITestCase):
    @property
    def endpoint_path(self):
        return reverse("authentication:list_or_create_users")

    def check_create(self, status_code, args=None):
        self.client.force_authenticate(StaffUserFactory())
        response = self.client.post(self.endpoint_path, args, format="json")
        self.assertEqual(response.status_code, status_code)

        return response.json()

    def test_create_with_no_existing_user(self):
        new_email = "newuser@test.com"
        args = {"email": new_email, "password": VALID_PASSWORD}
        response = self.check_create(200, args)

        new_user = User.objects.get(email=new_email)
        self.assertEqual(response["portunus_uuid"], str(new_user.portunus_uuid))

    def test_create_with_existing_user(self):
        user = UserFactory()
        response = self.check_create(400, {"email": user.email, "password": "asdf"})
        self.assertEqual(response["portunus_uuid"], user.portunus_uuid)
        self.assertEqual(response["user_exists"], True)

    @parameterized.expand([(False,), (True,)])
    def test_list_users(self, from_uuid):
        user1 = UserFactory()
        user2 = UserFactory()
        staff_user = StaffUserFactory()
        self.client.force_authenticate(staff_user)

        args = (
            {"portunus_uuids": [user1.portunus_uuid, user2.portunus_uuid]}
            if from_uuid
            else None
        )
        response = self.client.get(self.endpoint_path, args, format="json")
        self.assertEqual(response.status_code, 200)

        response_users = [user1, user2] if from_uuid else User.objects.none()
        self.assertCountEqual(response.json(), UserSerializer(response_users, many=True).data)

    def test_unauthenticated_user(self):
        response = self.client.get(self.endpoint_path)

        self.assertEqual(response.status_code, 401)


class TestSearchUsersView(APITestCase):
    @property
    def endpoint_path(self):
        return reverse("authentication:search_users")

    @parameterized.expand(
        [
            (
                False,
                False,
            ),
            (
                True,
                False,
            ),
            (
                True,
                True,
            ),
        ]
    )
    def test_search_email(self, use_email, search_substring):
        user1 = UserFactory(email="aaa@aaa.aaa")
        UserFactory(email="bbb@bbb.bbb")  # should not be returned by the search
        staff_user = StaffUserFactory(email="ccc@ccc.ccc")
        self.client.force_authenticate(staff_user)

        search_email = user1.email[:-3] if search_substring else user1.email
        args = {"search": search_email} if use_email else None
        response = self.client.get(self.endpoint_path, args, format="json")
        self.assertEqual(response.status_code, 200)

        response_users = [user1] if use_email else User.objects.none()
        self.assertCountEqual(response.json(), UserSerializer(response_users, many=True).data)

    def test_search_string(self):
        u = UserFactory(email="aaa@aaa.aaa")
        staff_user = StaffUserFactory(email="ccc@ccc.ccc")
        self.client.force_authenticate(staff_user)

        args = {"search": u.email[-MIN_SEARCH_LENGTH + 1 :]}
        response = self.client.get(self.endpoint_path, args, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 0)

        args = {"search": u.email[-MIN_SEARCH_LENGTH:]}
        response = self.client.get(self.endpoint_path, args, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 1)

    def test_result_limit(self):
        email_template = "aaa{}@aaa.aaa"
        for i in range(MAX_SEARCH_RESULTS + 1):
            UserFactory(email=email_template.format(i))

        staff_user = StaffUserFactory()
        self.client.force_authenticate(staff_user)

        args = {"search": email_template[-MIN_SEARCH_LENGTH:]}
        response = self.client.get(self.endpoint_path, args, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), MAX_SEARCH_RESULTS)


class TestRetrieveDeleteUserView(APITestCase):
    def setUp(self):
        self.user = UserFactory()

    @property
    def endpoint_path(self):
        return reverse(
            "authentication:retrieve_or_delete_user", args=[self.user.portunus_uuid]
        )

    def check_get(self, status_code):
        response = self.client.get(self.endpoint_path)
        self.assertEqual(response.status_code, status_code)

        if status_code == 200:
            self.assertDictEqual(response.data, UserSerializer(self.user).data)

    def check_delete(self, status_code=204):
        response = self.client.delete(self.endpoint_path)
        self.assertEqual(response.status_code, status_code)

        user = User.objects.filter(pk=self.user.pk).first()
        if status_code == 204:
            self.assertIsNone(user)
        else:
            self.assertIsNotNone(user)

    def check_user(self, user_requesting, status_code=None):
        if user_requesting:
            self.client.force_authenticate(user_requesting)

        self.check_get(status_code or 200)
        self.check_delete(status_code or 204)

    def test_same_user(self):
        self.check_user(self.user)

    def test_staff_user(self):
        staff_user = StaffUserFactory()
        self.client.force_authenticate(staff_user)
        self.check_get(200)
        self.check_delete(403)

    def test_superuser(self):
        superuser = SuperuserFactory()
        self.check_user(superuser)

    def test_wrong_user(self):
        other_user = UserFactory()
        self.check_user(other_user, status_code=403)

    def test_unauthenticated_user(self):
        self.check_user(None, status_code=401)
