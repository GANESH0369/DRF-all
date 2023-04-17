from django.contrib.auth.models import User
from rest_framework import routers, serializers
from rest_framework import exceptions
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .models import User


# class UserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         # fields = '__all__'
#         fields = ['username', 'password', 'email', 'first_name', 'last_name', 'mobile']

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        #fields = '__all__'
        fields = ['email','password']
     

            
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True, max_length=32)
    password = serializers.CharField(required=True,max_length=32)

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")
        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                if user.is_active:
                    data["user"] = user
                else:
                    msg = "account is not activated currently"
                    raise exceptions.ValidationError(msg)
            else:
                msg = "Invalid credentials"
                raise exceptions.ValidationError(msg)
        else:
            msg = "User name and password not empty"
            raise exceptions.ValidationError(msg)
        return data

# class Logoutseralizer(serializers.Serializer):
#     refresh = serializers.CharField()
#     default_error_messages = {
#         'bad_token' : ('Token is expired or invalid')
#     }

#     def validate(self, attrs):
#         self.token = attrs['refresh']
#         return attrs

#     def save(self, **kwargs):

#         try:
#             pass
#         except TokenError:
#             self.fail('bad_token')