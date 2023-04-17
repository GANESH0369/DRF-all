import json

from django.test import TestCase

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase


class UserTests(APITestCase):

    def test_create_user(self):
        """
        Ensure we can create a new account object.
        """
        url = '/app/user/create_user/'
        data = {'username': 'test', 'password': 'password1', 'email': 'test123@gmail.com',
                'first_name': 'ex', 'last_name': '1', 'mobile': '9848022338'}

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(json.loads(response.content), {"message": "user created successfully"})

    def test_authenticate_user(self):
        """
        Ensure we can create a new account object.
        """

        url = '/app/user/authenticate_user/'
        data = {'username': 'test123@gmail.com', 'password': 'password1'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(json.loads(response.content), {"status": "error", "msg": "The username/password specified is not valid."})



