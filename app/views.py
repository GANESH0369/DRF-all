import datetime
import json
import logging
from django.contrib.auth.models import User, Group
from app.serializers import UserSerializer,LoginSerializer
from django.shortcuts import HttpResponse, render,redirect
from django.views import View
from django.http import JsonResponse
from rest_framework import status
from django_service import settings
from django.shortcuts import get_object_or_404, get_list_or_404, render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import User
from rest_framework_jwt.settings import api_settings
from django.contrib.auth import authenticate
from django.db.models import Q
from drf_yasg.utils import swagger_auto_schema
from django.contrib import auth, messages
from drf_yasg import openapi
from django.http import HttpResponse
from app.encrypt_decrypt import encrypt, decrypt
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token 
from pymongo import MongoClient
# from mongoengine import Document, StringField
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)


logger = logging.getLogger("django_service.service.views")

# SECRET_KEY='1234567'
# class signup(APIView):
#     @swagger_auto_schema(
#         operation_id='Sign up',
#         request_body=UserSerializer)
#     def post(self,request,format=None):
#         # import pdb;pdb.set_trace()
#         serializer = UserSerializer(data=json.loads(request.body))
#         data = serializer.initial_data
#         password = data.get("password")
#         password= encrypt(bytes(password, "utf-8"), SECRET_KEY.encode()).decode()
#         data["password"] = password
#         if serializer.is_valid():
#             serializer.save()
#         return JsonResponse({"message": "user created successfully"}, status=status.HTTP_201_CREATED)
    
# logger = logging.getLogger("django_service.service.views")

SECRET_KEY='1234567'
class signup(APIView):
    @swagger_auto_schema(
        operation_id='Sign up',
        request_body=UserSerializer)
    def post(self,request,format=None):
        # import pdb;pdb.set_trace()
        serializer = UserSerializer(data=json.loads(request.body))
        data = serializer.initial_data
        password = data.get("password")
        password= encrypt(bytes(password, "utf-8"), SECRET_KEY.encode()).decode()
        data["password"] = password
        email=data.get("email")
        if User.objects.filter(email=email).exists():  
            return JsonResponse({"status": "error", "msg": "Email already exists"})
        else:
            serializer.is_valid()
            serializer.save()
            return JsonResponse({"message": "user created successfully"}, status=status.HTTP_201_CREATED)

#---------------------------------------------------------------------------------------------------------------
# client = MongoClient('mongodb://localhost:27017')
# db = client['demofile']
# class AuthenticateUser(APIView):
#     @swagger_auto_schema(request_body=openapi.Schema(
#         type=openapi.TYPE_OBJECT,
#         properties={
#             'username': openapi.Schema(type=openapi.TYPE_STRING, description='username '),
#             'password': openapi.Schema(type=openapi.TYPE_STRING, description='password'),
#         }
#     ))
#     def post(self, request, format=None):
#         # import pdb;pdb.set_trace()        
#         data = json.loads(request.body)
#         # exact=data["password"]
#         # newpass_1= decrypt(bytes(exact, "utf-8"), SECRET_KEY.encode()).decode()
#         # x=newpass_1
#         user = User.objects.filter(Q(username__iexact=data["username"]) | Q(password__iexact=data["password"])).first()
#         if user is not None:
#             username=data.get("username")
#             password_1=data.get("password")
#             newpass_2= decrypt(bytes(password_1, "utf-8"), SECRET_KEY.encode()).decode() 
#             m= newpass_2          
#             if username and m:
#                 newpass_3= decrypt(bytes(password_1, "utf-8"), SECRET_KEY.encode())
#                 y=newpass_3.decode()
#                 if  m == y:
#                     user = authenticate(username=data["username"], password=password_1)
#                     token, created = Token.objects.get_or_create(user=user)
#                     if user.id is not None:
#                     # Store the token in MongoDB
#                         collection = db['tokens']
#                         token_data = {"user_id": user.id, "key": token.key}
#                         collection.insert_one(token_data)

#                         return JsonResponse({"status": "success", "msg": "user successfully authenticated", "token": token.key})
#                     else:
#                         return JsonResponse({"status": "error", "msg": "user has no id"})

        
#                 # return JsonResponse({"status": "success", "msg": "user successfully authenticated", "token": token.key})
#         else:
#             return JsonResponse({"status": "error", "msg": "incorrect username or password"})
#------------------------------------------------------------------------------------------------------
client = MongoClient('mongodb://localhost:27017')
db = client['demofile']
mycol = db["tokendb_1"]

class AuthenticateUser(APIView):#Working man
    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='email'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='password')
        }
    ))
    def post(self, request, format=None):
        # import pdb;pdb.set_trace()
        data = json.loads(request.body)
        user = User.objects.filter(Q(email__iexact=data["email"])).first()
        if user is not None:
            encrypted_password = user.password
            decrypted_password = decrypt(bytes(encrypted_password, "utf-8"), SECRET_KEY.encode()).decode()

            x= decrypted_password
            if x == data["password"]:
                token, created = Token.objects.get_or_create(user=user)
                mycol.insert_one({
                "user_id": str(user.id),
                "token": token.key,
                "created_at": datetime.datetime.now()
                })
                return JsonResponse({"status": "success", "msg": "user successfully authenticated", "token": token.key})
            else:
                return JsonResponse({"status": "error", "msg": "incorrect password"})
        else:
            return JsonResponse({"status": "error", "msg": "incorrect email"})
#-----------------------------------------------------------------------------------------------------------------


#----------------------------------------------------------------------------------------------------------------
class ChangePassword(APIView):
    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'username': openapi.Schema(type=openapi.TYPE_STRING, description='username or email'),
            'oldpassword': openapi.Schema(type=openapi.TYPE_STRING, description='Type old password'),
            'newpassword': openapi.Schema(type=openapi.TYPE_STRING, description='Type new password')
        }
    ))
    def post(self, request, format=None):
        #import pdb;pdb.set_trace()
        #import pdb;pdb.set_trace()
        data = json.loads(request.body)
        user = User.objects.filter(Q(username__iexact=data["username"]) | Q(password__iexact=data["oldpassword"])).first()
        if user is not None:
            #username = data.get("username")
            password = data.get("oldpassword")
            new_password = data["newpassword"]
            key_1=decrypt(bytes(password,"utf-8"), SECRET_KEY.encode()).decode() 
                        #newpass_2= decrypt(bytes(password_1, "utf-8"), SECRET_KEY.encode()).decode() 
            if key_1 != new_password:
                user.set_password("newpassword")
                user.save()
                return JsonResponse({"message": "user password updated successfully"})
                                
            return JsonResponse({"message": "worng password."}, status=status.HTTP_400_BAD_REQUEST)

#--------------------------------------------------------------------------------------------------------
class LogoutView(APIView):
    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
           properties={
            'token': openapi.Schema(type=openapi.TYPE_STRING, description='refresh_token')
        }
     ))
    def post(self, request):
        refresh_token = {'token':"U2FsdGVkX19/FxRrKmASgQw3j83WES5jj5xtOvSgmzc="}
        if not refresh_token:
            return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
#---------------------------------------------------------------------------------------------------------
# class LogoutAPIViews(APIView):
#     serializer_class = Logoutseralizer
#     permission_classes = (IsAuthenticated,)
    

#     def post(self, request):
#         serializer = self.request_body(data = request.data)
#         serializer.is_valid(raise_exception = True)
#         serializer.save()

#         return Response(status=status.HTTP_204_NO_CONTENT)  


# class logout(APIView):
#     permission_classes = (IsAuthenticated,)
#     #@method_decorator(required_login)
#     def post(self, request, *args, **kwargs):
#         import pdb;pdb.set_trace()
#         refresh_token = request.data.get(token.key)
#         token = RefreshToken(refresh_token)
#         is_blackListed = token.blacklist()
#         result = CommonResult(
#             status.HTTP_200_OK,
#             "SUCCESS",
#             "Successful Logout"
#         )
#         return result.http_response()
#         user.auth_token.delete()
#         return Response({"detail": "Successfully logged out."}, status=200)


class GetAllUsers(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        """
        API endpoint that fetch all users.
        """
        users_data = User.objects.all().order_by('-date_joined')
        user_serializer = UserSerializer(users_data, many=True, context={'request': request})
        return JsonResponse({"users": user_serializer.data})


class GetUserById(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, pk):
        """
        API endpoint that fetch user by id.
        """
        queryset = User.objects.filter(id=pk)
        serializer_user = UserSerializer(queryset, many=True, context={'request': request})
        return JsonResponse({"users": serializer_user.data})


class ProfileView(APIView):
    permission_classes = (IsAuthenticated, )
    def get(self, request, format=None):
        data = dict()
        data['username'] = request.user.username
        data['email'] = request.user.email
        data['user_id'] = request.user.pk
        logger.info("User data %s", data)
        return Response(data)
