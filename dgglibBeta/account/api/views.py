import pytz
from django.utils import timezone
from django.shortcuts import render, redirect
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, renderer_classes, permission_classes
from django.http import JsonResponse
from rest_framework import status
from rest_framework import generics, permissions, mixins
from account.models import RegisterUser, Folder, Profile, FolderFile, DeletedFileFolder, ShareFile, NonRegisterFolderFile \
    ,UploadFiles2, RecoveryDeletedFileFolder
from account.models import userfeedback as Feedback
from django.db.models import Q
import os.path
import shutil
import sys
import datetime
# from datetime import datetime
import collections
from collections import Counter
import re
from django.core.files import File
from django.core import signing
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.template.loader import render_to_string, get_template
from django.core.mail import EmailMessage
from urllib.parse import urlparse
from django.contrib.auth.models import User, auth
from passlib.hash import pbkdf2_sha256
from django.conf import settings
from django.http import HttpResponse
from rest_framework.decorators import api_view, renderer_classes
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from django.core.files.base import ContentFile
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth import authenticate
from django.conf import settings
from django.http import HttpResponse
import json
from django.contrib.auth.tokens import default_token_generator
from email_validator import validate_email, EmailNotValidError
from django.urls import reverse

from .serializers import FileDownloadSerializer, FolderFileSerializer, TrashSerializer, ChangePasswordSerializer, ProfileSerializer, FolderSerializer, UserDisplaySerializer, MemberSerializer, FolderUploadSerializer
from .validatemymail import *
from django.http import *
import mimetypes
import random
import string
import os
import os.path
from os import path
import pathlib
from pathlib import Path
from digilockerbackend import settings
from digilockerbackend.settings import ROOT_URL
from digilockerbackend.settings import MEDIA_ROOT, EMAIL_HOST_USER
from digilockerbackend.settings import ZIP_ROOT
from uuid import uuid4
import urllib.request
import secrets
from django.template import loader
from django.core.mail import send_mail
from django.core import mail
from django.core.mail import EmailMessage

from django.template.loader import render_to_string
from django.utils.html import strip_tags
import smtplib
import shutil
from shutil import copyfile
import zipfile
from io import StringIO
import time
from datetime import datetime, date, time, timedelta, timezone
import random
import glob
from zipfile import ZipFile
from django.db.models import Count
from .utils import get_icon, get_real_filesize
# from .utils import rename_file_folder
# import linkpreview
# from linkpreview import Link, LinkPreview, LinkGrabber
# from django.contrib.auth.models import User
# from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import requests




def email_activation_login(request, *args, **kwargs):
    uid = kwargs.get('uidb64')
    print(uid)
    if uid:
        decoded_user_id = urlsafe_base64_decode(uid)
        print(decoded_user_id)
        user = RegisterUser.objects.get(id=decoded_user_id)
        user.active_email = True
        user.save()
        return render(request, 'digital_locker_signin.html')


class RegisterAPIView(APIView):
    #this class  used for registration of new user that is called from an ajax in signup html
    model = RegisterUser
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        user_id = data.get('user_id')
        password = data.get('password')
        email = data.get('email')
        display_name = data.get('display_name')
        hash_pass = pbkdf2_sha256.encrypt(password, rounds=12000, salt_size=32)
        qs = RegisterUser.objects.filter(Q(user_id__iexact=user_id) | Q(email__iexact=email))
        if qs.count() == 0:
            new_user = RegisterUser(user_id=user_id, password=hash_pass, email=email, display_name=display_name, active_email = False)
            new_user.save()
            user = User.objects.create_user(username=user_id, password=hash_pass, email=email,
                                            first_name=display_name)
            user.save()
            auth_user = User.objects.get(username=user_id)
            token=default_token_generator.make_token(auth_user)
            token_user = RegisterUser.objects.get(user_id=user_id)
            token_user.token = token
            token_user.save()

            try:
                url = settings.ROOT_URL
                ctx = {
                    'user':new_user.user_id,
                    'content': url,
                    'uid':urlsafe_base64_encode(force_bytes(new_user.id)),
                    'token': token,
                    }
                sender_email = settings.EMAIL_HOST_USER
                message = get_template('activition_email.html').render(ctx)
                msg = EmailMessage(
                'Account Activition Email - Digilocker',
                message,
                sender_email,
                [email],
                )
                msg.content_subtype = "html"  # Main content is now text/html
                msg.send()

            except Exception as e:
                print(e)

            response = {
                    'status': "success",
                    'code': status.HTTP_200_OK,
                    'message': 'An Activation has send to your email address.To activate your account as a registered account and Login for the 1st time, you have to click on that link'
                    }
        else:
            response = {
                    'status': "error",
                    'code': status.HTTP_200_OK,
                    'message': 'This User id  or Email already taken, please choose another one.'
                    }
        return Response(response)


class LoginAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        user_id = data.get('user_id')
        password = data.get('password')
        user = RegisterUser.objects.get(user_id=user_id, active_email = True)

        hash_data = user.verify_password(password)
        if hash_data == True:
            profile_pic = str(user.profile_pic)
            request.session['user_id'] = user.id
            default_size = int(user.default_size)
            uploaded_size = int(user.uploaded_size)
            remaining_size = default_size - uploaded_size
            token = user.token
            if profile_pic:
                response = {
                    'status': 'ok',
                    'token': token,
                    'user_id': user.user_id,
                    'remaining_size': remaining_size,
                }
            else:
                response = {
                    'status': 'ok',
                    'token': token,
                    'user_id': user.user_id,
                    'remaining_size': remaining_size,
                }
        else:
            response = {
                'status': 'error',
                'message': 'please check your user id or password'
            }
        return Response(response)





class FolderListAPIView(APIView):

    permission_classes = [permissions.AllowAny]

    def get(self, request, id):

        user_id = request.get('user_id')
        folders = Folder.objects.all().filter(user_id_id=id)
        folder_files = FolderFile.objects.filter(folder_id=id).filter(user_id_id=user_id)
        serializer = FolderSerializer(folders, many=True)
        return Response(serializer.data)


class MemberListAPIView(APIView):

    permission_classes = [permissions.AllowAny]

    def get(self, request):
        members = RegisterUser.objects.all()
        serializer = MemberSerializer(members, many=True)
        return Response(serializer.data)


class UserDisplayAPIView(APIView):

    permission_classes = [permissions.AllowAny]

    def get(self, request):
        user_display = RegisterUser.objects.filter()
        serializer = UserDisplaySerializer(user_display, many=True)
        return Response(serializer.data)


class ProfileViewAPI(APIView):

    permission_classes = [permissions.AllowAny]

    def get(self, request):
        profile_id = request.data.get('profile_id')
        profile_display = Profile.objects.all().filter(profile_id=profile_id)
        serializer = ProfileSerializer(profile_display, many=True)
        return Response(serializer.data)

    def post(self, request):
        data = request.data
        serializer = ProfileSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfilePicAPIView(APIView):

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        user_id = data.get('id')
        user = RegisterUser.objects.get(id=user_id)
        profile_pic = str(user.profile_pic)
        base_dir = settings.ROOT_URL
        image_url = base_dir+'media/'+profile_pic
        response = {
            'image_url': image_url
        }
        return Response(response)


class UpdateProfilePicView(APIView):
    """
    this classed used to change profile picture of a user
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.FILES
        pic = data.get('profile_pic')
        user_id = request.data.get('user_id')
        usr = RegisterUser.objects.get(token=user_id)
        usr_pic = pic
        usr.profile_pic = usr_pic
        str_pic = str(usr.profile_pic)
        base_dir = settings.ROOT_URL
        usr.save()
        # srt_pic = base_dir+'media/'+str(usr.profile_pic)
        srt_pic = os.path.join(base_dir, 'media', str(usr.profile_pic))
        return redirect(srt_pic)


def usernameupdate(request):
    if request.method == "POST":
        username = request.POST['username']
        print(username)
        user_id = request.POST['user_id']
        usr = RegisterUser.objects.get(token=user_id)
        usr.display_name = username
        usr.save()
        return redirect('index')

def foldernameupdate(request):
    if request.method == "POST":
        val = request.POST['foldername']
        folder_id = request.POST['folder_id']
        user_id = request.session['user_id']
        if (Folder.objects.filter(folder_name=val, user_id_id=user_id).exists()):
            if str(val).isdigit():
                val = int(val)
                val += 1
                folder_name = val
            else:
                if val[-1].isdigit():
                    res = [re.findall(r'(\w+?)(\d+)', val)[0]]
                    number = res[0][1]
                    same_name = res[0][0]
                    val = str(same_name)+str(int(number)+1)
                    folder_name = val
                else:
                    val += str(1)
                    folder_name = val

            folder = Folder.objects.get(id=folder_id, user_id_id=user_id)
            folder.folder_name = folder_name
            folder.save()
            response = {
                'status': 'Success',
                'message': 'Name Updated'
            }
            return JsonResponse(response)

class FolderRenameAPI(APIView):

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        foldername = request.POST.get('foldername')
        folder_id = request.POST.get('folder_id')
        #user_id = request.session['user_id']
        user_id = request.POST.get('user_id')
        if (Folder.objects.filter(folder_name=foldername, user_id_id=user_id).exists()):
            print("folder found")
            response = {
                'status': 'Failed',

                'message': 'Name not Updated'
            }
            return JsonResponse(response)
        else:
            print('renamed')
            folder = Folder.objects.get(id=folder_id, user_id_id=user_id)
            folder.folder_name = foldername
            folder.save()
            response = {
                'status': 'Success',

                'message': 'Name Updated'
            }
            return JsonResponse(response)



def filenameupdate(request):
    if request.method == "POST":
        filename = request.POST['filename']
        folder_id = request.POST['folder_id']
        file_id = request.POST['file_id']
        user_id = request.session['user_id']

        folderfile = FolderFile.objects.get(
            id=file_id, folder_id=folder_id, user_id_id=user_id)
        oldfilepath = str(folderfile.only_file_name)
        filepath_with_name = str(folderfile.file_name)
        path, filenamee = os.path.split(filepath_with_name)
        filenamee = os.path.splitext(filename)[0]
        filename_, file_extension = os.path.splitext(filepath_with_name)
        newfilename_ = filename + file_extension
        if (newfilename_ == oldfilepath):
            response = {
                'status': 'Failed',
                'message': 'Name not Updated'
            }
            return JsonResponse(response)
        else:
            new_filepath_with_name = os.path.join(path,  newfilename_)
            folderfile.file_name = new_filepath_with_name
            oldfile_fullpath = os.path.join(settings.MEDIA_ROOT, str(
                user_id), str(folder_id), str(oldfilepath))
            if os.path.exists(oldfile_fullpath):
                full_file_name = Path(oldfilepath).name
                old_file_name = os.path.splitext(full_file_name)[0]
                old_file_ext = os.path.splitext(full_file_name)[1]
                new_file_name = filename.split('.')[0]
                new_file_ext = old_file_ext
                new_file_name_with_ext = new_file_name + new_file_ext
                folderfile.only_file_name = new_file_name_with_ext
                folderfile.save()
                new_file_path = os.path.join(settings.MEDIA_ROOT, str(
                    user_id), str(folder_id), new_file_name_with_ext)
                try:
                    os.rename(oldfile_fullpath, new_file_path)
                    print("Source path renamed to destination path successfully.")

                except OSError as error:
                    print(error)
            response = {
                'status': 'Success',

                'message': 'Name Updated'
            }
            return JsonResponse(response)


class UpdatePasswordView(APIView):
    """
    this classed used to change profile picture of a user
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        p_pass = data.get('p_pass')
        password = data.get('password')
        cnf_pass = data.get('cnf_pass')
        user_id = request.data.get('user_id')
        usr = RegisterUser.objects.get(token=user_id)
        hash_data = usr.verify_password(p_pass)
        if hash_data == True:
            hash_pass = pbkdf2_sha256.encrypt(
                password, rounds=12000, salt_size=32)
            usr.password = hash_pass
            usr.save()

            response = {
                'status': 'Success',
                'code': status.HTTP_200_OK,
                'message': 'Password Updated '
            }
            return Response(response)
        else:
            response = {
                'status': 'Failed',
                'code': status.HTTP_304_NOT_MODIFIED,
                'message': 'previous Password incorrect'
            }
            return Response(response )


def frgt_pass(request):
    """
    this function used to render forget_pass html file
    """
    return render(request, 'forget_pass.html')


def Emaildata(request, *args, **kwargs):
    """
    this function loads the html page from the link that is given to the user's email account for password verification
    """
    return render(request, 'change_pass.html')


class ForgetPassID(APIView):
    """
    this class takes used id and checkes if user register or not, if registered it returens its id
    """
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        data = request.data
        email = data.get('email')
        user = RegisterUser.objects.get(email=email)
        if user:
            try:
                token=user.token
                ctx = {
                'user':user.user_id,
                'content':'http://www.dgglib.in:8000',###forget pass url don not put / at the end
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                'token': token,
                }
                message = get_template('sendmail.html').render(ctx)
                msg = EmailMessage(
                'Reset password',
                message,
                settings.EMAIL_HOST_USER,
                [email],
                )
                msg.content_subtype = "html"  # Main content is now text/html
                msg.send()
            except Exception as e:
                print(e)
            response={
                'status':'success',
                'code':status.HTTP_200_OK,
                'message':'a mail send to your email account.please reset your password by clicking the link inside that email'
            }
        return Response(response)


class ForgotPasswordAPI(APIView):

    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data
        email = data.get('user_id')
        user = RegisterUser.objects.get(email=email)
        if user:
            token = user.token
            ctx = {
                'user': user.user_id,
                'content': 'http:'
            }

class UserNewPass(APIView):
    """
    this class used to change password to a new one in case when a user forget's his/her password
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data
        uid = data.get('uid')
        password = data.get('password')
        user_id = urlsafe_base64_decode(uid)
        current_user = RegisterUser.objects.get(id=user_id)
        if current_user is not None:
            hash_pass = pbkdf2_sha256.encrypt(
                password, rounds=12000, salt_size=32)
            current_user.password = hash_pass
            current_user.save()
            response = {
                'status': 'success',
                 'code': status.HTTP_200_OK,
                'message': 'Password updated successfully.Log in to your account with new password',
            }
            return Response(response)


def _handle_uploaded_file(folder_id, file, login_user_id):
    """
    this function calls from  AddFolderView class and takes folderid, file ,user id and stores all those into FolderFile table in digilocker_db database
    """
    folder_id = folder_id

    if '/' in str(os):
        item_folder = '{}/{}'.format(login_user_id, folder_id)
        item_name = item_folder+'/'+file.name
        full_filename = os.path.join(
            settings.MEDIA_ROOT, item_folder, file.name)
        fout = open(full_filename, 'wb+')
        file_content = ContentFile(file.read())
        for chunk in file_content.chunks():
            fout.write(chunk)
        fout.close()
        file_insert = FolderFile(
            user_id_id=login_user_id, folder_id=folder_id, file_name=item_name)
        file_insert.save()
    else:
        item_folder = '{}\{}'.format(login_user_id, folder_id)
        full_filename = os.path.join(
            settings.MEDIA_ROOT, item_folder, file.name)
        only_file_name = file.name
        print(only_file_name)
        fout = open(full_filename, 'wb+')
        file_content = ContentFile(file.read())
        for chunk in file_content.chunks():
            fout.write(chunk)
        fout.close()
        file_insert = FolderFile(user_id_id=login_user_id, folder_id=folder_id,
                                 file_name=full_filename, only_file_name=only_file_name)
        file_insert.save()
    all_files = FolderFile.objects.all()
    for items in all_files:
        if items.file_name == "":
            items.delete()

class UploadFolderAPIView(APIView):

    serializer_class = FolderUploadSerializer
    queryset = FolderFile.objects.all()

    def post(self, request, *args, **kwargs):
        data = None

class AddFolderView(APIView):
    """
    this class takes files ,foldername, user id and create folder and add all the files to that folder and add those to Folderfile table in database.to add files to its repective folder it calls
    _handle_uploaded_file(folder_id,afile,login_user_id) function , that is just above this class

    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        files = request.FILES.getlist('files')
        login_user_token = request.data.get('add_user_id')
        login_user = RegisterUser.objects.get(token=login_user_token)
        defautlt_size = login_user.default_size
        login_user_id = login_user.id
        folder_name = request.data.get('folder_name')
        total_folder_size = int(request.data.get('total_size'))
        login_user.uploaded_size = int(
            login_user.uploaded_size) + int(total_folder_size)
        login_user.save()
        if (Folder.objects.filter(folder_name=folder_name, user_id_id=login_user_id).exists()):
            val = folder_name
            while(Folder.objects.filter(folder_name=val, user_id_id=login_user_id).exists()):
                if val[-1].isdigit():
                    res = [re.findall(r'(\w+?)(\d+)', val)[0]]
                    number = res[0][1]
                    same_name = res[0][0]
                    val = str(same_name)+str(int(number)+1)
                    folder_name = val
                else:
                    val += str(1)
                    folder_name = val

        folder = Folder(folder_name=folder_name, user_id_id=login_user_id)
        folder.save()
        request.session['folder_id'] = folder.id
        folder_id = request.session['folder_id']
        path = 'media/{}/{}'.format(login_user_id, folder.id)
        os.makedirs(path)
        for afile in files:
            _handle_uploaded_file(folder_id, afile, login_user_id)
        default_size = int(login_user.default_size)
        uploaded_size = int(login_user.uploaded_size)
        remaining_size = default_size - uploaded_size
        all_folder_files = FolderFile.objects.filter(folder_id=folder_id)
        all_folder = Folder.objects.filter(user_id_id=login_user_id).count()
        json_list = []
        json_list.append(folder_name)
        json_list.append(folder_id)
        json_list.append(login_user_id)
        json_list.append(all_folder)
        json_list.append(remaining_size)
        excel_file_icon = '<i class="fa fa-file-excel-o" style="font-size:30px;color:#3CB371"></i>'
        pdf_file_icon = '<i class="fa fa-file-pdf-o" style="font-size:30px;color:#DC143C" aria-hidden="true"></i>'
        word_file_icon = '<i class="fa fa-file-word-o" style="font-size:30px;color:#00BFFF;" aria-hidden="true"></i>'
        text_icon = '<i class="fa fa-file-text" style="font-size:30px;color:#808080;" aria-hidden="true"></i>'
        zip_file_icon = '<i class="fa fa-file-archive-o"  style="font-size:30px;color:#FFA500" aria-hidden="true"></i>'
        mp3_icon = '<i class="fas fa-music" style="font-size:30px;color:#FF6600"></i>'
        mp4_icon = '<i class="fa fa-play" style="font-size:30px;color:#FF00CC" aria-hidden="true"></i>'
        for items in all_folder_files:
            url = str(items.file_name)
            a = urlparse(url)
            file_name = os.path.basename(a.path)
            name, ext = os.path.splitext(file_name)
            if ext.lower() == '.jpg' or ext.lower() == '.jpeg' or ext.lower() == '.png':
                json_list.append({
                    'item': items.file_name.url, 'file_name': file_name, 'icon': '', 'item_id': items.id
                })
            elif ext.lower() == '.xlsx':
                json_list.append({
                    'item': items.file_name.url, 'file_name': file_name, 'icon': excel_file_icon, 'item_id': items.id
                })
            elif ext.lower() == '.pdf':
                json_list.append({
                    'item': items.file_name.url, 'file_name': file_name, 'icon': pdf_file_icon, 'item_id': items.id
                })
            elif ext.lower() == '.docx':
                json_list.append({
                    'item': items.file_name.url, 'file_name': file_name, 'icon': word_file_icon, 'item_id': items.id
                })
            elif ext.lower() == '.txt':
                json_list.append({
                    'item': items.file_name.url, 'file_name': file_name, 'icon': text_icon, 'item_id': items.id
                })
            elif ext.lower() == '.zip':
                json_list.append({
                    'item': items.file_name.url, 'file_name': file_name, 'icon': zip_file_icon, 'item_id': items.id
                })
            elif ext.lower()  == '.mp3':
                json_list.append({
                    'item': "", 'file_name': file_name, 'icon': mp3_icon, 'item_id': items.id
                })
            elif ext.lower() == '.mkv' or ext.lower() == '.mp4' or ext.lower() == '.flv' or ext.lower() == '.avi' or ext.lower() == '.wmv' or ext.lower() == '.m4p' or ext.lower() == '.m4v' or ext.lower() == '.mpg' or ext.lower() == '.mp2' or ext.lower() == '.mpeg' or ext.lower() == '.mpe' or ext.lower() == '.nsv' or ext.lower() == '.3gp' or ext.lower() == '.mpv':
                json_list.append({
                    'item': "", 'file_name': file_name, 'icon': mp4_icon, 'item_id': items.id
                })
        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')


class CreateFolderView(APIView):
    """
    this class used to create folder manually
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        response = {}
        data = request.data
        login_user_token = data.get('create_user_id')
        login_user = RegisterUser.objects.get(token=login_user_token)
        login_user_id = login_user.id
        folder_name = data.get('create_folder_name')
        if (Folder.objects.filter(folder_name=folder_name, user_id_id=login_user_id).exists()):
            val = folder_name
            while(Folder.objects.filter(folder_name=val, user_id_id=login_user_id).exists()):

                if str(val).isdigit():
                    val = int(val)
                    val += 1
                    folder_name = val
                else:
                    if val[-1].isdigit():
                        res = [re.findall(r'(\w+?)(\d+)', val)[0]]
                        number = res[0][1]
                        same_name = res[0][0]
                        val = str(same_name)+str(int(number)+1)
                        folder_name = val
                    else:
                        val += str(1)
                        folder_name = val

        folder = Folder(folder_name=folder_name, user_id_id=login_user_id)
        folder.save()
        all_folder = Folder.objects.filter(user_id_id=login_user_id).count()
        path = 'media/{}/{}'.format(login_user_id, folder.id)
        os.makedirs(path)
        response = {
            'status': 'ok',
            'folder_name': folder.folder_name,
            'folder_id': folder.id,
            'login_user_id': login_user_id,
            'all_folder_count': all_folder,
        }
        return Response(response)


def _handle_uploaded_newfile(folder_id, file, login_user_id):
    """
    this function  called by AddFileView class and by the class it get folder id, files and user id and by those it add files to its respective folder and
    to Folderfile table in digilocker_db database
    """
    folder_id = folder_id
    if '/' in str(os):
        item_folder = '{}/{}'.format(login_user_id, folder_id)
        item_name = item_folder+'/'+file.name
        full_filename = os.path.join(
            settings.MEDIA_ROOT, item_folder, file.name)
        only_file_name = file.name
        fout = open(full_filename, 'wb+')
        file_content = ContentFile(file.read())
        for chunk in file_content.chunks():
            fout.write(chunk)
        fout.close()
        file_insert = FolderFile(user_id_id=login_user_id, folder_id=folder_id,
                                 file_name=item_name, only_file_name=only_file_name)

        try:
            save_status = file_insert.save()
            print(save_status)
        except Exception as e:
            print("Exception due to {} ",e)
            response = {
                'status': 'failed',
                'message': 'File name already exists, please rename'
            }
            return Response(response)

    else:
        item_folder = '{}\{}'.format(login_user_id, folder_id)
        full_filename = os.path.join(
            settings.MEDIA_ROOT, item_folder, file.name)
        only_file_name = file.name
        fout = open(full_filename, 'wb+')
        file_content = ContentFile(file.read())
        for chunk in file_content.chunks():
            fout.write(chunk)
        fout.close()
        file_insert = FolderFile(user_id_id=login_user_id, folder_id=folder_id,
                                 file_name=full_filename, only_file_name=only_file_name)
        try:
            save_status = file_insert.save()
            print(save_status)
        except Exception as e:
            print("Exception due to {} ",e)
            response = {
                'status': 'failed',
                'message': 'File name already exists, please rename '
            }
            return Response(response)
        print(save_status)
    all_files = FolderFile.objects.all()
    for items in all_files:
        if items.file_name == "":
            items.delete()


class AddFileView(APIView):
    """
    this class used to add files to manually created folder and to Folderdfile table in digilocker_db database. to add files it calls
    _handle_uploaded_newfile(folder_id,afile,login_user_id) function that is just above this class

    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        dt_started = datetime.now(timezone.utc)
        print(dt_started)
        files = request.FILES.getlist('files')
        login_user_id = request.data.get('add_user_id')
        login_user = RegisterUser.objects.get(id=login_user_id)
        folder_id = request.data.get('folder_id')
        total_fsize = int(request.data.get('total_fsize'))
        login_user.uploaded_size = int(
            login_user.uploaded_size) + int(total_fsize)
        login_user.save()
        for afile in files:
            _handle_uploaded_newfile(folder_id, afile, login_user_id)

        default_size = int(login_user.default_size)
        uploaded_size = int(login_user.uploaded_size)
        remaining_size = default_size - uploaded_size
        all_files = FolderFile.objects.filter(folder_id=folder_id)
        json_list = []
        excel_file_icon = '<i class="fa fa-file-excel-o" style="font-size:30px;color:#3CB371"></i>'
        pdf_file_icon = '<i class="fa fa-file-pdf-o" style="font-size:30px;color:#DC143C" aria-hidden="true"></i>'
        word_file_icon = '<i class="fa fa-file-word-o" style="font-size:30px;color:#00BFFF;" aria-hidden="true"></i>'
        text_icon = '<i class="fa fa-file-text" style="font-size:30px;color:#808080;" aria-hidden="true"></i>'
        zip_file_icon = '<i class="fa fa-file-archive-o"  style="font-size:30px;color:#FFA500" aria-hidden="true"></i>'
        mp3_icon = '<i class="fas fa-music" style="font-size:30px;color:#FF6600"></i>'
        mp4_icon = '<i class="fa fa-play" style="font-size:30px;color:#FF00CC" aria-hidden="true"></i>'
        json_list.append(folder_id)
        json_list.append(remaining_size)
        for items in all_files:
            url = str(items.file_name)
            a = urlparse(url)
            file_name = os.path.basename(a.path)
            name, ext = os.path.splitext(file_name)
            if ext.lower() == '.jpg' or ext.lower() == '.jpeg' or ext.lower() == '.png':
                json_list.append({
                    'item': items.file_name.url, 'file_name': file_name, 'icon': '', 'item_id': items.id
                })
            elif ext.lower() == '.xlsx':
                json_list.append({
                    'item': items.file_name.url, 'file_name': file_name, 'icon': excel_file_icon, 'item_id': items.id
                })
            elif ext.lower() == '.pdf':
                json_list.append({
                    'item': items.file_name.url, 'file_name': file_name, 'icon': pdf_file_icon, 'item_id': items.id
                })
            elif ext.lower () == '.docx':
                json_list.append({
                    'item': items.file_name.url, 'file_name': file_name, 'icon': word_file_icon, 'item_id': items.id
                })
            elif ext.lower() == '.txt':
                json_list.append({
                    'item': items.file_name.url, 'file_name': file_name, 'icon': text_icon, 'item_id': items.id
                })
            elif ext.lower() == '.zip':
                json_list.append({
                    'item': items.file_name.url, 'file_name': file_name, 'icon': zip_file_icon, 'item_id': items.id
                })
            elif ext.lower() == '.mp3':
                json_list.append({
                     'item': "", 'file_name': file_name, 'icon': mp3_icon, 'item_id': items.id
                })
            elif ext.lower() == '.mkv' or ext.lower() == '.mp4' or ext.lower() == '.flv' or ext.lower() == '.avi' or ext.lower() == '.wmv' or ext.lower() == '.m4p' or ext.lower() == '.m4v' or ext.lower() == '.mpg' or ext.lower() == '.mp2' or ext.lower() == '.mpeg' or ext.lower() == '.mpe' or ext.lower() == '.nsv' or ext.lower() == '.3gp' or ext.lower() == '.mpv':
                json_list.append({
                    'item': "", 'file_name': file_name, 'icon': mp4_icon, 'item_id': items.id
                })
        data = json.dumps(json_list)
        dt_ended = datetime.now(timezone.utc)
        print(dt_ended)
        return HttpResponse(data, content_type='application/json')


def DeleteSingleItem(request):
    if request.method == 'POST':
        data = request.POST
        user_id = request.session['user_id']
        login_user = RegisterUser.objects.get(id=user_id)
        file_id = data.get('file_id')
        print(file_id)
        current_file = FolderFile.objects.get(id=int(file_id))

    response = {'status': 'file deleted'}

    #data = json.dumps(response)
    # return redirect('index')
    return HttpResponse(data, content_type='application/json')


class DeleteItemView(APIView):
    """
    this class handels deletion of files in a folder
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):

        data = request.data
        print(data)
        # item_ids = request.POST['detete_files_ids']
        # print(item_ids)
        # sys.exit()
        item_ids = data.get('detete_files_ids')
        delete_files_ids = item_ids.split(",")
        for item_id in delete_files_ids:

            current_file = FolderFile.objects.get(id=int(item_id))
            user_id = current_file.user_id_id
            login_user = RegisterUser.objects.get(id=user_id)
            folder_id = current_file.folder_id
            folder = Folder.objects.get(id=folder_id)
            folder_name = folder.folder_name
            current_file_name = current_file.file_name
            # current_file_path = os.path.join(settings.MEDIA_ROOT, str(user_id), str(current_file_name))
            current_file_path = os.path.join(settings.MEDIA_ROOT, str(current_file_name))
            print(current_file_path)
            print(os.path.isfile(current_file_path))
            print('his')

            fsize = os.stat(current_file_path)
            print(fsize)
            ori_fsizekb = round(fsize.st_size/1024)
            login_user.uploaded_size = int(
                login_user.uploaded_size) - int(ori_fsizekb)
            login_user.save()
            url = str(current_file_name)
            a = urlparse(url)

            file_name = os.path.basename(a.path)
            deleted_file = DeletedFileFolder()
            deleted_file.file_name = current_file_name
            deleted_file.folder_name = folder_name
            deleted_file.user_id_id = user_id
            deleted_file.save()
            # if os.path.isfile(current_file_path):
            #     os.remove(str(current_file_path))

            current_file.delete()
            all_files = FolderFile.objects.filter(folder_id=folder_id)
            json_list = []
            excel_file_icon = '<i class="fa fa-file-excel-o" style="font-size:30px;color:#3CB371"></i>'
            pdf_file_icon = '<i class="fa fa-file-pdf-o" style="font-size:30px;color:#DC143C" aria-hidden="true"></i>'
            word_file_icon = '<i class="fa fa-file-word-o" style="font-size:30px;color:#00BFFF;" aria-hidden="true"></i>'
            text_icon = '<i class="fa fa-file-text" style="font-size:30px;color:#808080;" aria-hidden="true"></i>'
            zip_file_icon = '<i class="fa fa-file-archive-o"  style="font-size:30px;color:#FFA500" aria-hidden="true"></i>'
            mp3_icon = '<i class="fas fa-music" style="font-size:30px;color:#FF6600"></i>'
            mp4_icon = '<i class="fa fa-play" style="font-size:30px;color:#FF00CC" aria-hidden="true"></i>'
            json_list.append(folder_id)
            for items in all_files:
                url = str(items.file_name)
                a = urlparse(url)
                file_name = os.path.basename(a.path)
                name, ext = os.path.splitext(file_name)
                if ext.lower() == '.jpg' or ext.lower() == '.jpeg' or ext.lower() == '.png':
                    json_list.append({
                        'item': items.file_name.url, 'file_name': file_name, 'icon': '', 'item_id': items.id
                    })
                elif ext.lower() == '.xlsx':
                    json_list.append({
                        'item': items.file_name.url, 'file_name': file_name, 'icon': excel_file_icon, 'item_id': items.id
                    })
                elif ext.lower() == '.pdf':
                    json_list.append({
                        'item': items.file_name.url, 'file_name': file_name, 'icon': pdf_file_icon, 'item_id': items.id
                    })
                elif ext.lower() == '.docx':
                    json_list.append({
                        'item': items.file_name.url, 'file_name': file_name, 'icon': word_file_icon, 'item_id': items.id
                    })
                elif ext.lower() == '.txt':
                    json_list.append({
                        'item': items.file_name.url, 'file_name': file_name, 'icon': text_icon, 'item_id': items.id
                    })
                elif ext.lower() == '.zip':
                    json_list.append({
                        'item': items.file_name.url, 'file_name': file_name, 'icon': zip_file_icon, 'item_id': items.id
                    })
                elif ext.lower() == '.mp3':
                    json_list.append({
                        'item': "", 'file_name': file_name, 'icon': mp3_icon, 'item_id': items.id
                    })
                elif ext.lower() == '.mkv' or ext.lower() == '.mp4' or ext.lower() == '.flv' or ext.lower() == '.avi' or ext.lower() == '.wmv' or ext.lower() == '.m4p' or ext.lower() == '.m4v' or ext.lower() == '.mpg' or ext.lower() == '.mp2' or ext.lower() == '.mpeg' or ext.lower() == '.mpe' or ext.lower() == '.nsv' or ext.lower() == '.3gp' or ext.lower() == '.mpv':
                    json_list.append({
                        'item': "", 'file_name': file_name, 'icon': mp4_icon, 'item_id': items.id
                    })
        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')



class DeleteSharedItemView(APIView):
    """
    this class handels deletion of files in a folder
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):

        data = request.data
        print(data)
        # item_ids = request.POST['detete_files_ids']
        # print(item_ids)
        # sys.exit()
        item_ids = data.get('detete_files_ids')
        delete_files_ids = item_ids.split(",")
        for item_id in delete_files_ids:

            current_file = ShareFile.objects.get(id=int(item_id))
            # user_id = current_file.user_id_id
            # login_user = RegisterUser.objects.get(id=user_id)
            # folder_id = current_file.folder_id
            # folder = Folder.objects.get(id=folder_id)
            # folder_name = folder.folder_name
            # current_file_name = current_file.file_name
            # # current_file_path = os.path.join(settings.MEDIA_ROOT, str(user_id), str(current_file_name))
            # current_file_path = os.path.join(settings.MEDIA_ROOT, str(current_file_name))

            # fsize = os.stat(current_file_path)
            # print(fsize)
            # ori_fsizekb = round(fsize.st_size/1024)
            # login_user.uploaded_size = int(
            #     login_user.uploaded_size) - int(ori_fsizekb)
            # login_user.save()
            # url = str(current_file_name)
            # a = urlparse(url)

            # file_name = os.path.basename(current_file.file_id)
            deleted_file = DeletedFileFolder()
            deleted_file.file_name = current_file.file_id
            deleted_file.folder_name = current_file.sender_name
            deleted_file.user_id_id = current_file.reciver_id_id
            deleted_file.shared = 1
            deleted_file.save()
            # if os.path.isfile(current_file_path):
            #     os.remove(str(current_file_path))

            current_file.delete()
            # all_files = FolderFile.objects.filter(folder_id=folder_id)
            # json_list = []
            # excel_file_icon = '<i class="fa fa-file-excel-o" style="font-size:30px;color:#3CB371"></i>'
            # pdf_file_icon = '<i class="fa fa-file-pdf-o" style="font-size:30px;color:#DC143C" aria-hidden="true"></i>'
            # word_file_icon = '<i class="fa fa-file-word-o" style="font-size:30px;color:#00BFFF;" aria-hidden="true"></i>'
            # text_icon = '<i class="fa fa-file-text" style="font-size:30px;color:#808080;" aria-hidden="true"></i>'
            # zip_file_icon = '<i class="fa fa-file-archive-o"  style="font-size:30px;color:#FFA500" aria-hidden="true"></i>'
            # mp3_icon = '<i class="fas fa-music" style="font-size:30px;color:#FF6600"></i>'
            # mp4_icon = '<i class="fa fa-play" style="font-size:30px;color:#FF00CC" aria-hidden="true"></i>'
            # json_list.append(folder_id)
            # for items in all_files:
            #     url = str(items.file_name)
            #     a = urlparse(url)
            #     file_name = os.path.basename(a.path)
            #     name, ext = os.path.splitext(file_name)
            #     if ext.lower() == '.jpg' or ext.lower() == '.jpeg' or ext.lower() == '.png':
            #         json_list.append({
            #             'item': items.file_name.url, 'file_name': file_name, 'icon': '', 'item_id': items.id
            #         })
            #     elif ext.lower() == '.xlsx':
            #         json_list.append({
            #             'item': items.file_name.url, 'file_name': file_name, 'icon': excel_file_icon, 'item_id': items.id
            #         })
            #     elif ext.lower() == '.pdf':
            #         json_list.append({
            #             'item': items.file_name.url, 'file_name': file_name, 'icon': pdf_file_icon, 'item_id': items.id
            #         })
            #     elif ext.lower() == '.docx':
            #         json_list.append({
            #             'item': items.file_name.url, 'file_name': file_name, 'icon': word_file_icon, 'item_id': items.id
            #         })
            #     elif ext.lower() == '.txt':
            #         json_list.append({
            #             'item': items.file_name.url, 'file_name': file_name, 'icon': text_icon, 'item_id': items.id
            #         })
            #     elif ext.lower() == '.zip':
            #         json_list.append({
            #             'item': items.file_name.url, 'file_name': file_name, 'icon': zip_file_icon, 'item_id': items.id
            #         })
            #     elif ext.lower() == '.mp3':
            #         json_list.append({
            #             'item': "", 'file_name': file_name, 'icon': mp3_icon, 'item_id': items.id
            #         })
            #     elif ext.lower() == '.mkv' or ext.lower() == '.mp4' or ext.lower() == '.flv' or ext.lower() == '.avi' or ext.lower() == '.wmv' or ext.lower() == '.m4p' or ext.lower() == '.m4v' or ext.lower() == '.mpg' or ext.lower() == '.mp2' or ext.lower() == '.mpeg' or ext.lower() == '.mpe' or ext.lower() == '.nsv' or ext.lower() == '.3gp' or ext.lower() == '.mpv':
            #         json_list.append({
            #             'item': "", 'file_name': file_name, 'icon': mp4_icon, 'item_id': items.id
            #         })
        json_list = []
        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')



class LogOutView(APIView):
    """
    this class handels logout portion
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data
        login_user_token = data.get('user_id')
        login_user = RegisterUser.objects.get(token=login_user_token)
        if login_user:
            del request.session['user_id']
        auth.logout(request)
        response = {
            'status': 'success',
            'code': status.HTTP_200_OK,
            "message": "You are successfully logged out..come again later"
        }
        return Response(response)


class SearchFolderView(APIView):
    """
    this class handels search any folder by its name
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data
        user_id = request.session['user_id']
        folder_name_text = data.get('folder_text')
        if folder_name_text != "":
            folders = Folder.objects.filter(
                Q(folder_name__icontains=folder_name_text), user_id=user_id)
            folderfile = FolderFile.objects.filter(
                Q(only_file_name__icontains=folder_name_text), user_id=user_id)
        else:
            folders = Folder.objects.filter(user_id=user_id)
            folderfile = FolderFile.objects.filter(user_id=user_id)
        json_list = []

        folders_file=[]
        #lst_folder=[]
        for items in folders:
            folder_list={}
            products=[]
            folder_files = FolderFile.objects.filter(folder_id = items.id).filter(user_id_id = user_id)
            print("folder id =",items.id,"user id =",user_id)
            #print(len(folder_files))
            for item2 in folder_files:

                fileprods={}
                fileprods['image']=item2.only_file_name
                fileprods['file_name']=str(item2.file_name)#needs some manupulation here with the link
                fileprods['file_id']=item2.id
                fileprods['icon']=' '
                products.append(fileprods)

            folder_list['folder_id']=items.id
            folder_list["folder_name"]=items.folder_name
            folder_list["user_id"]=items.user_id_id
            folder_list["products"]=products
            folder_list["count"]='co'
            folder_list["real_size"]='re'

            folders_file.append(folder_list)


        print(folders_file)

        for item in folders:
                json_list.append({
                    'folder_name':item.folder_name,'folder_id':item.id,'type':'folder',"files":[{"link":"somelink","name":"somename","file_id":"file_id"}]
                })

        for item in folderfile:
                json_list.append({
                    'file_name':item.only_file_name,'file_id':item.id,'type':'file'
                })

        data = json.dumps(json_list)

        return HttpResponse(data, content_type='application/json')


class SearchPeopleView(APIView):
    """
    this class handels search people by their name
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data
        user_id = request.session['user_id']
        people_name_text = data.get('people_text')
        if people_name_text != "":
            users = RegisterUser.objects.filter(
                Q(user_id__icontains=people_name_text))
        else:
            users = RegisterUser.objects.all()[0:5]
        json_list = []
        # default_image = '{% static "images/inner1_NEW.png" %}'
        default_image = '/static/images/inner1_NEW.png'
        for item in users:
            if item.profile_pic:
                json_list.append({
                    'user_id': item.user_id, 'image': item.profile_pic.url
                })
            else:
                json_list.append({
                    'user_id': item.user_id, 'image': default_image
                })

        data = json.dumps(json_list)
        print("search people")
        return HttpResponse(data, content_type='application/json')

class DeleteAppendAPI(APIView):

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        user_id = request.session['user_id_id']
        delete_folder_file = []
        current_user_item = DeletedFileFolder.objects.filter(
                user_id_id=user_id).order_by('-id')[0:7]
        for item in current_user_item:
            url = str(item.file_name)
            a = urlparse(url)
            file_name = os.path.basename(a.path)
            if item.file_name:
                delete_folder_file.append({
                        'folder': item.folder_name, 'file_url': item.file_name.url, 'file_name': file_name, 'file_id': item.id
                    })
            else:
                delete_folder_file.append({
                        'folder': item.folder_name, 'file_url': item.file_name, 'file_name': file_name, 'file_id': item.id
                    })
        data = json.dumps(delete_folder_file)
        return HttpResponse(data, content_type='application/json')

############################################################### OK #################################################################################


def share_render(request, *args, **kwargs):
    """
    this function loads the html page from the link that is given to the user's email account to view his/her shared item
    """
    uid = kwargs.get('uidb64')
    decoded_user_id = urlsafe_base64_decode(uid)
    token = kwargs.get('token')
    shared_file = ShareFile.objects.filter(reciver_id_id=decoded_user_id, token=token, reciver_checked=False)
    for item in shared_file:
        item.reciver_checked = True
        item.save()
    return render(request, 'digital_locker_signin.html')


def share_render_folder(request, *args, **kwargs):
    """
    this function loads the html page from the link that is given to the user's email account to view his/her shared item
    """
    uid = kwargs.get('uidb64')
    decoded_user_id = urlsafe_base64_decode(uid)
    token = kwargs.get('token')
    shared_file = ShareFile.objects.filter(reciver_id_id=decoded_user_id, token=token, reciver_checked=False)
    for item in shared_file:
        item.reciver_checked = True
        item.save()
    return render(request, 'digital_locker_signin.html')


def shared_pagi(request):
#"""
 #this functions handels pagination section of Shared Item portion]
#"""
    user_id = request.session['user_id']
    page= int(request.GET.get('page', None))
    request.session['page_no_share_page'] = page
    starting_number= (page-1)*7
    ending_number= page*7
    shared_item = ShareFile.objects.filter(reciver_id_id=user_id,reciver_checked=True).order_by('-id')[starting_number:ending_number]
    shared_item_list=[]
    shared_item_list.append(starting_number)
    for item in shared_item:
        if item.file_id !="":
             url =str(item.file_id)
             a = urlparse(url)
             file_name = os.path.basename(a.path)
             shared_item_list.append({
                     'sender_name':item.sender_name ,'file_url':item.file_id.url,'file_name':file_name,'file_id':item.id
            })
    data = json.dumps(shared_item_list)
    return HttpResponse(data, content_type='application/json')





class SharePeopleFolder(APIView):
    """
    this class handels share foloder to desired register user by logged in user
    """
    permission_classes = [permissions.AllowAny]

    def post(self,request,*args,**kwargs):
        data = request.data
        loggedin_user_id = request.session['user_id']
        loggedin_user = RegisterUser.objects.get(id=loggedin_user_id)
        loggedin_user_name = loggedin_user.user_id
        data = request.data
        folder_id = data.get('share_folder_id')
        folder_files = FolderFile.objects.filter(folder_id=folder_id)
        recived_people = data.get('share_people_ids')
        recived_people_id = recived_people.split(",")
        for people_id in recived_people_id:
            usr = RegisterUser.objects.get(id=int(people_id))
            email =usr.email
            user_token=usr.token
            token = secrets.token_hex(20)
            _handle_sharefolder(loggedin_user_name,usr.user_id,loggedin_user_id,usr.id,folder_id,token)
        try:

            ctx = {
            'recived_user':usr.user_id,
            'send_user':loggedin_user_name,
            'content':ROOT_URL,
            'uid':urlsafe_base64_encode(force_bytes(usr.pk)),
            # 'folder_id':urlsafe_base64_encode(force_bytes(int(folder_id))),
            'token': token,
            }

            message = get_template('sendfolderlink.html').render(ctx)
            msg = EmailMessage(
            'File Sending Notification',
            message,
            settings.EMAIL_HOST_USER,
            [email],
            )
            msg.content_subtype = "html"  # Main content is now text/html
            msg.send()
            response={
            'status':'success',
            'code':status.HTTP_200_OK,
            'message':'Link has been shared with the intended user'
            }
            return Response(response)

        except Exception as e:
            print(e)
            response={
                'status':'error',
                'code':status.HTTP_200_OK,
                'message':'Something error there!'
            }
            return Response(response)



def _handle_sharefolder(loggedin_user_name, reciver, sender_id, reciver_id, folder_id, token):
    print("_handle_sharefolder")
    base_dir = settings.BASE_DIR
    source = base_dir+'/media/{}/{}/'.format(sender_id, folder_id)
    for filename in os.listdir(source):
        share_file = ShareFile()
        share_file.sender_name = loggedin_user_name
        share_file.reciver_checked = False
        share_file.reciver_id_id = reciver_id
        share_file.reciver = reciver
        share_file.token = token
        share_file.save()
        with open(source+filename, 'rb') as f:
            django_file = File(f)
            info = {'name': filename, 'reciver_id': reciver_id}
            try:
                share_file.file_id.save(info, django_file, save=True)
            except Exception as e:
                print(e)


class SharedSharePeopleFolder(APIView):
    """
    this class handels share foloder to desired register user by logged in user
    """
    permission_classes = [permissions.AllowAny]

    def post(self,request,*args,**kwargs):
        data = request.data
        loggedin_user_id = request.session['user_id']
        loggedin_user = RegisterUser.objects.get(id=loggedin_user_id)
        loggedin_user_name = loggedin_user.user_id
        data = request.data

        recived_people = data.get('share_people_ids')
        recived_people_id = recived_people.split(",")
        for people_id in recived_people_id:
            usr = RegisterUser.objects.get(id=int(people_id))
            email =usr.email
            folder_id = data.get('share_folder_id')
            folder_files = ShareFile.objects.filter(sender_name=folder_id, reciver=loggedin_user_name)
            token = secrets.token_hex(20)

            _handle_sharedsharefolder(loggedin_user_name, usr.user_id, loggedin_user_id, usr.id, token, folder_files)

        try:

            ctx = {
            'recived_user':usr.user_id,
            'send_user':loggedin_user_name,
            'content':ROOT_URL,
            'uid':urlsafe_base64_encode(force_bytes(usr.pk)),
            # 'folder_id':urlsafe_base64_encode(force_bytes(int(folder_id))),
            'token': token,
            }

            message = get_template('sendfolderlink.html').render(ctx)
            msg = EmailMessage(
            'File Sending Notification',
            message,
            settings.EMAIL_HOST_USER,
            [email],
            )
            msg.content_subtype = "html"  # Main content is now text/html
            msg.send()
            response={
            'status':'success',
            'code':status.HTTP_200_OK,
            'message':'Link has been shared with the intended user'
            }
            return Response(response)

        except Exception as e:
            print(e)
            response={
                'status':'error',
                'code':status.HTTP_200_OK,
                'message':'Something error there!'
            }
            return Response(response)


class TrashSharePeopleFolder(APIView):
    """
    this class handels share foloder to desired register user by logged in user
    """
    permission_classes = [permissions.AllowAny]

    def post(self,request,*args,**kwargs):
        data = request.data
        loggedin_user_id = request.session['user_id']
        loggedin_user = RegisterUser.objects.get(id=loggedin_user_id)
        loggedin_user_name = loggedin_user.user_id
        data = request.data

        recived_people = data.get('share_people_ids')
        recived_people_id = recived_people.split(",")
        for people_id in recived_people_id:
            usr = RegisterUser.objects.get(id=int(people_id))
            email =usr.email
            folder_id = data.get('share_folder_id')
            folder_files = DeletedFileFolder.objects.filter(folder_name=folder_id, is_deleted=False, user_id_id=loggedin_user_id)
            token = secrets.token_hex(20)

            _handle_trashsharefolder(loggedin_user_name, usr.user_id, loggedin_user_id, usr.id, token, folder_files)

        try:

            ctx = {
            'recived_user':usr.user_id,
            'send_user':loggedin_user_name,
            'content':ROOT_URL,
            'uid':urlsafe_base64_encode(force_bytes(usr.pk)),
            # 'folder_id':urlsafe_base64_encode(force_bytes(int(folder_id))),
            'token': token,
            }

            message = get_template('sendfolderlink.html').render(ctx)
            msg = EmailMessage(
            'File Sending Notification',
            message,
            settings.EMAIL_HOST_USER,
            [email],
            )
            msg.content_subtype = "html"  # Main content is now text/html
            msg.send()
            response={
            'status':'success',
            'code':status.HTTP_200_OK,
            'message':'Link has been shared with the intended user'
            }
            return Response(response)

        except Exception as e:
            print(e)
            response={
                'status':'error',
                'code':status.HTTP_200_OK,
                'message':'Something error there!'
            }
            return Response(response)

def _handle_trashsharefolder(loggedin_user_name, reciver, sender_id, reciver_id, token, folder_files):
    for files in folder_files:
        media_file_path = os.path.join(MEDIA_ROOT, str(files.file_name))
        filename = os.path.basename(media_file_path)
        if os.path.isfile(media_file_path):
            share_file = ShareFile()
            share_file.sender_name = loggedin_user_name
            share_file.reciver_checked = False
            share_file.reciver_id_id = reciver_id
            share_file.reciver = reciver
            share_file.token = token
            share_file.save()
            with open(media_file_path, 'rb') as f:
                django_file = File(f)
                info = {'name': filename, 'reciver_id': reciver_id}
                try:
                    share_file.file_id.save(info, django_file, save=True)
                except Exception as e:
                    print(e)


def _handle_sharedsharefolder(loggedin_user_name, reciver, sender_id, reciver_id, token, folder_files):
    for files in folder_files:
        media_file_path = os.path.join(MEDIA_ROOT, str(files.file_id))
        filename = os.path.basename(media_file_path)
        if os.path.isfile(media_file_path):
            share_file = ShareFile()
            share_file.sender_name = loggedin_user_name
            share_file.reciver_checked = False
            share_file.reciver_id_id = reciver_id
            share_file.reciver = reciver
            share_file.token = token
            share_file.save()
            with open(media_file_path, 'rb') as f:
                django_file = File(f)
                info = {'name': filename, 'reciver_id': reciver_id}
                try:
                    share_file.file_id.save(info, django_file, save=True)
                except Exception as e:
                    print(e)

    #         pass
    #     print(media_file_path)
    # print("_handle_sharefolder")
    # base_dir = settings.BASE_DIR
    # source = base_dir+'/media/shared_files/{}/'.format(sender_id)
    # print(source)
    # sys.exit()
    # for filename in os.listdir(source):
    #     share_file = ShareFile()
    #     share_file.sender_name = loggedin_user_name
    #     share_file.reciver_checked = False
    #     share_file.reciver_id_id = reciver_id
    #     share_file.reciver = reciver
    #     share_file.token = token
    #     share_file.save()
    #     with open(source+filename, 'rb') as f:
    #         django_file = File(f)
    #         info = {'name': filename, 'reciver_id': reciver_id}
    #         try:
    #             share_file.file_id.save(info, django_file, save=True)
    #         except Exception as e:
    #             print(e)


class SharePeopleSharedFile(APIView):
    """
    this class handels share files to desired register user by logged in user
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data

        loggedin_user_id = request.session['user_id']
        loggedin_user = RegisterUser.objects.get(id=loggedin_user_id)
        loggedin_user_name = loggedin_user.user_id
        data = request.data
        item_ids = data.get('share_files_ids')
        share_files_ids = item_ids.split(",")
        recived_people = data.get('share_people_ids')
        recived_people_id = recived_people.split(",")

        for user_id in recived_people_id:
            usr = RegisterUser.objects.get(id=int(user_id))
            email = usr.email
            token = secrets.token_hex(20)
            for item_id in share_files_ids:
                file = ShareFile.objects.get(id=int(item_id))
                file_name = file.file_id
                _handle_share_shared_file(loggedin_user_name, usr.user_id,
                                loggedin_user_id, file_name, usr.id, token),

                # deleted_file = DeletedFileFolder.objects.filter(file_name=file_name)
                # for items in deleted_file:
                #     items.shared = True
                #     items.save()
        try:

            ctx = {
                'recived_user': usr.user_id,
                'send_user': loggedin_user_name,
                'content': ROOT_URL,
                'uid': urlsafe_base64_encode(force_bytes(usr.pk)),
                'token': token,
            }
            message = get_template('sendfilelink.html').render(ctx)
            msg = EmailMessage(
                'File Sending Notification',
                message,
                settings.EMAIL_HOST_USER,
                [email],
            )
            msg.content_subtype = "html"  # Main content is now text/html
            msg.send()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'a mail send to your email account.please reset your password by clicking the link inside that email'
            }
            return Response(response)

        except Exception as e:
            print(e)
            response = {
                'status': 'error',
                'code': status.HTTP_200_OK,
                'message': 'Something error there!'
            }
        return Response(response)


class SharePeopleTrashFile(APIView):
    """
    this class handels share files to desired register user by logged in user
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data

        loggedin_user_id = request.session['user_id']
        loggedin_user = RegisterUser.objects.get(id=loggedin_user_id)
        loggedin_user_name = loggedin_user.user_id
        data = request.data
        item_ids = data.get('share_files_ids')
        share_files_ids = item_ids.split(",")
        recived_people = data.get('share_people_ids')
        recived_people_id = recived_people.split(",")

        for user_id in recived_people_id:
            usr = RegisterUser.objects.get(id=int(user_id))
            email = usr.email
            token = secrets.token_hex(20)
            for item_id in share_files_ids:
                file = DeletedFileFolder.objects.get(id=int(item_id))
                file_name = file.file_name
                _handle_share_shared_file(loggedin_user_name, usr.user_id,
                                loggedin_user_id, file_name, usr.id, token),

                # deleted_file = DeletedFileFolder.objects.filter(file_name=file_name)
                # for items in deleted_file:
                #     items.shared = True
                #     items.save()
        try:

            ctx = {
                'recived_user': usr.user_id,
                'send_user': loggedin_user_name,
                'content': ROOT_URL,
                'uid': urlsafe_base64_encode(force_bytes(usr.pk)),
                'token': token,
            }
            message = get_template('sendfilelink.html').render(ctx)
            msg = EmailMessage(
                'File Sending Notification',
                message,
                settings.EMAIL_HOST_USER,
                [email],
            )
            msg.content_subtype = "html"  # Main content is now text/html
            msg.send()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'a mail send to your email account.please reset your password by clicking the link inside that email'
            }
            return Response(response)

        except Exception as e:
            print(e)
            response = {
                'status': 'error',
                'code': status.HTTP_200_OK,
                'message': 'Something error there!'
            }
        return Response(response)

def _handle_share_shared_file(loggedin_user_name, reciver, sender_id, afile, reciver_id, token):
    base_dir = settings.BASE_DIR
    media_path = base_dir+'/media/'
    # url = str(afile)
    # a = urlparse(url)
    # file_name = source+str(os.path.basename(a.path))
    share_file = ShareFile()
    share_file.sender_name = loggedin_user_name
    share_file.reciver_checked = False
    share_file.reciver_id_id = reciver_id
    share_file.reciver = reciver
    share_file.token = token
    share_file.save()
    with open(media_path+str(afile), 'rb') as f:
        django_file = File(f)
        info = {'name': afile, 'reciver_id': reciver_id}
        share_file.file_id.save(info, django_file, save=True)





class SharePeopleFile(APIView):
    """
    this class handels share files to desired register user by logged in user
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data
        loggedin_user_id = request.session['user_id']
        loggedin_user = RegisterUser.objects.get(id=loggedin_user_id)
        loggedin_user_name = loggedin_user.user_id
        data = request.data
        item_ids = data.get('share_files_ids')
        share_files_ids = item_ids.split(",")
        recived_people = data.get('share_people_ids')
        recived_people_id = recived_people.split(",")
        try:
            for user_id in recived_people_id:
                usr = RegisterUser.objects.get(id=int(user_id))
                email = usr.email
                token = secrets.token_hex(20)
                for item_id in share_files_ids:
                    file = FolderFile.objects.get(id=int(item_id))
                    file_name = file.file_name
                    folder_id = file.folder_id
                    _handle_sharefile(loggedin_user_name, usr.user_id,
                                    loggedin_user_id, file_name, usr.id, folder_id, token),

                    deleted_file = DeletedFileFolder.objects.filter(file_name=file_name)
                    for items in deleted_file:
                        items.shared = True
                        items.save()
                ctx = {
                    'recived_user': usr.user_id,
                    'send_user': loggedin_user_name,
                    'content': ROOT_URL,
                    'uid': urlsafe_base64_encode(force_bytes(usr.pk)),
                    'token': token,
                }
                message = get_template('sendfilelink.html').render(ctx)
                msg = EmailMessage(
                    'File Sending Notification',
                    message,
                    settings.EMAIL_HOST_USER,
                    [email],
                )
                msg.content_subtype = "html"  # Main content is now text/html
                msg.send()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'a mail send to your email account.please reset your password by clicking the link inside that email'
            }
            return Response(response)

        except Exception as e:
            print(e)
            response = {
                'status': 'error',
                'code': status.HTTP_200_OK,
                'message': 'Something error there!'
            }
            return Response(response)



def _handle_sharefile(loggedin_user_name, reciver, sender_id, afile, reciver_id, folder_id, token):
    base_dir = settings.BASE_DIR
    source = base_dir + f'/media/{sender_id}/{folder_id}/'
    media_path = base_dir+'/media/'
    url = str(afile)
    a = urlparse(url)
    file_name = source+str(os.path.basename(a.path))
    share_file = ShareFile()
    share_file.sender_name = loggedin_user_name
    share_file.reciver_checked = False
    share_file.reciver_id_id = reciver_id
    share_file.reciver = reciver
    share_file.token = token
    share_file.save()
    with open(media_path+str(afile), 'rb') as f:
        django_file = File(f)
        info = {'name': afile, 'reciver_id': reciver_id}
        share_file.file_id.save(info, django_file, save=True)




def member_ajax_right(request):
    data = ""
    if request.method == "GET":
        TOTAL = 6
        OFFSET = int(request.GET['offset'])
        END = OFFSET + TOTAL
        result = RegisterUser.objects.all()[OFFSET:END]
        count = RegisterUser.objects.all().count()-6
        json_list = []
        json_list.append(count)
        json_list.append(OFFSET)
        default_image = '/static/images/inner1_NEW.png'
        for item in result:
            if item.profile_pic:
                json_list.append({
                    'user_id': item.user_id, 'image': item.profile_pic.url
                })
            else:
                json_list.append({
                    'user_id': item.user_id, 'image': default_image
                })

        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')


def member_ajax_left(request):
    data = ""
    if request.method == "GET":
        user_id = request.session['user_id']
        TOTAL = 6
        OFFSET = int(request.GET['offset'])
        END = OFFSET + TOTAL
        result = RegisterUser.objects.exclude(id=user_id)[OFFSET:END]
        json_list = []
        json_list.append(OFFSET)
        default_image = '/static/images/inner1_NEW.png'
        for item in result:
            if item.profile_pic:
                json_list.append({
                    'user_id': item.user_id, 'image': item.profile_pic.url
                })
            else:
                json_list.append({
                    'user_id': item.user_id, 'image': default_image
                })

        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')


def trash_ajax_right(request):
    user_id = request.session['user_id']
    if request.method == "GET":
        TOTAL = 7
        OFFSET = int(request.GET['offset'])
        END = OFFSET + TOTAL
        request.session['trash_offset'] = OFFSET
        request.session['trash_end'] = END
        result = DeletedFileFolder.objects.filter(
            user_id_id=user_id).order_by('-id')[OFFSET:END]
        count = DeletedFileFolder.objects.filter(user_id_id=user_id).count()-7
        json_list = []
        json_list.append(count)
        json_list.append(OFFSET)
        for item in result:
            url = str(item.file_name)
            a = urlparse(url)
            file_name = os.path.basename(a.path)
            json_list.append({
                'folder_name': item.folder_name, 'file': item.file_name.url, 'file_name': file_name, 'file_id': item.id
            })

        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')


def trash_ajax_left(request):
    user_id = request.session['user_id']
    if request.method == "GET":
        TOTAL = 7
        OFFSET = int(request.GET['offset'])
        END = OFFSET + TOTAL
        request.session['trash_offset'] = OFFSET
        request.session['trash_end'] = END
        result = DeletedFileFolder.objects.filter(
            user_id_id=user_id).order_by('-id')[OFFSET:END]
        json_list = []
        json_list.append(OFFSET)
        for item in result:
            url = str(item.file_name)
            a = urlparse(url)
            file_name = os.path.basename(a.path)
            json_list.append ({
                'folder_name': item.folder_name, 'file': item.file_name.url, 'file_name': file_name, 'file_id': item.id
            })

        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')


class trashItemDeleteView(APIView):
    """
    this class handel's deletion of trash item
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        print(request.POST)
        #user_id = request.session['user_id']
        data = request.data
        user_id = data.get('user_id')
        trash_ids = data.get('trash_files_ids')
        trash_files_ids = trash_ids.split(",")

        for item in trash_files_ids:
            trash_item = DeletedFileFolder.objects.get(id=item)
            if trash_item.shared == False:
                if '/' in str(os):
                    full_path = os.path.join(
                        settings.MEDIA_ROOT, str(trash_item.file_name))
                    os.remove(full_path)
                else:
                    trash_path = trash_item.file_name
                trash_item.delete()
            else:
                trash_item.delete()
        OFFSET = request.session['trash_offset']
        END = request.session['trash_end']
        json_list = []
        new_delete_files = DeletedFileFolder.objects.filter(
            user_id_id=user_id).order_by('-id')[OFFSET:END]
        for item in new_delete_files:
            url = str(item.file_name)
            a = urlparse(url)
            file_name = os.path.basename(a.path)
            json_list.append({
                'folder_name': item.folder_name, 'file': item.file_name.url, 'file_name': file_name, 'file_id': item.id
            })

        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')



class trash_all_Item_DeleteView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data
        user_id = request.session['user_id']
        all_trash = DeletedFileFolder.objects.filter(user_id_id=user_id)
        for item in all_trash:
            if item.shared == False:
                full_path = os.path.join(settings.MEDIA_ROOT, str(item.file_name))
                if os.path.exists(full_path):
                    os.remove(full_path)
            item.delete()
        response = {
            'status': 'success',
        }
        return Response(response)


def share_ajax_right(request):
    user_id = request.session['user_id']
    if request.method == "GET":
        TOTAL = 7
        OFFSET = int(request.GET['offset'])
        END = OFFSET + TOTAL
        request.session['share_offset'] = OFFSET
        request.session['share_end'] = END
        shared_item = ShareFile.objects.filter(
            reciver_id_id=user_id, reciver_checked=True).order_by('-id')[OFFSET:END]
        count = ShareFile.objects.filter(
            reciver_id_id=user_id, reciver_checked=True).count()-7
        shared_item_list = []
        shared_item_list.append(count)
        shared_item_list.append(OFFSET)
        for item in shared_item:
            if item.file_id != "":
                url = str(item.file_id)
                a = urlparse(url)
                file_name = os.path.basename(a.path)
                shared_item_list.append({
                    'sender_name': item.sender_name, 'file_url': item.file_id.url, 'file_name': file_name, 'file_id': item.id
                })

        data = json.dumps(shared_item_list)
        return HttpResponse(data, content_type='application/json')


def share_ajax_left(request):
    user_id = request.session['user_id']
    if request.method == "GET":
        TOTAL = 7
        OFFSET = int(request.GET['offset'])
        END = OFFSET + TOTAL
        request.session['share_offset'] = OFFSET
        request.session['share_end'] = END
        shared_item = ShareFile.objects.filter(
            reciver_id_id=user_id, reciver_checked=True).order_by('-id')[OFFSET:END]
        shared_item_list = []
        shared_item_list.append(OFFSET)
        for item in shared_item:
            if item.file_id != "":
                url = str(item.file_id)
                a = urlparse(url)
                file_name = os.path.basename(a.path)
                shared_item_list.append({
                    'sender_name': item.sender_name, 'file_url': item.file_id.url, 'file_name': file_name, 'file_id': item.id
                })

        data = json.dumps(shared_item_list)
        return HttpResponse(data, content_type='application/json')


class SharedItemDeleteView(APIView):
    """
    this class handel's deletion of Shared item
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        user_id = request.session['user_id']
        data = request.data
        shared_item_id = data.get('shared_item_id')
        shared_item = ShareFile.objects.get(id=shared_item_id)
        deleted_file = DeletedFileFolder()
        deleted_file.file_name = shared_item
        deleted_file.user_id_id = user_id
        deleted_file.save()
        shared_item.delete()
        OFFSET = request.session['share_offset']
        END = request.session['share_end']
        json_list = []
        new_shared_files = ShareFile.objects.filter(
            reciver_id_id=user_id, reciver_checked=True).order_by('-id')[OFFSET:END]
        for item in new_shared_files:
            if item.file_id != "":
                url = str(item.file_id)
                a = urlparse(url)
                file_name = os.path.basename(a.path)
                json_list.append({
                    'sender_name': item.sender_name, 'file_url': item.file_id.url, 'file_name': file_name, 'file_id': item.id
                })

        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')


def folder_ajax_right(request):
    user_id = request.session['user_id']
    if request.method == "GET":
        TOTAL = 5
        OFFSET = int(request.GET['offset'])
        END = OFFSET + TOTAL
        request.session['folder_offset'] = OFFSET
        request.session['folder_end'] = END
        json_list = []
        my_folder = Folder.objects.filter(user_id_id=user_id)[OFFSET:END]
        count = Folder.objects.filter(user_id_id=user_id).count()-5
        json_list.append(count)
        for item in my_folder:
            json_list.append({
                'folder_name': item.folder_name, 'folder_id': item.id
            })

        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')


def folder_ajax_left(request):
    user_id = request.session['user_id']
    if request.method == "GET":
        TOTAL = 5
        OFFSET = int(request.GET['offset'])
        END = OFFSET + TOTAL
        request.session['folder_offset'] = OFFSET
        request.session['folder_end'] = END
        json_list = []
        my_folder = Folder.objects.filter(user_id_id=user_id)[OFFSET:END]
        count = Folder.objects.filter(user_id_id=user_id).count()-5
        for item in my_folder:
            json_list.append({
                'folder_name': item.folder_name, 'folder_id': item.id
            })

        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')


class DeleteFolderView(APIView):
    """
    this class handel's deletion of entire folder
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):

        data = request.data
        user_id = request.session['user_id']
        login_user = RegisterUser.objects.get(id=user_id)
        folder_id = data.get('folder_id')
        folder_lock = Folder.objects.get(id=folder_id)
        is_locked = folder_lock.is_locked
        if is_locked == True:
            return HttpResponse(json.dumps(['locked']), content_type='application/json')
        elif folder_id:
            current_folder = Folder.objects.get(id=folder_id)
            folder_name = current_folder.folder_name
            current_folder_files = FolderFile.objects.filter(
                folder_id=folder_id)
            print("current_folder", current_folder)
            for files in current_folder_files:
                deleted_file = DeletedFileFolder()
                if files.file_name:
                    file_name = files.file_name
                    current_f_path = os.path.join(
                        settings.MEDIA_ROOT, str(file_name))
                    fsize = os.stat(current_f_path)
                    ori_filesizekb = round(fsize.st_size/1024)
                    login_user.uploaded_size = int(
                        login_user.uploaded_size) - int(ori_filesizekb)
                    login_user.save()
                    url = str(file_name)
                    a = urlparse(url)
                    ori_file_name = os.path.basename(a.path)
                    deleted_file.file_name = file_name
                    deleted_file.folder_name = folder_name
                    deleted_file.user_id_id = user_id
                    deleted_file.save()

            current_folder.delete()
            if not current_folder_files.exists():
                all_deleted_folders = DeletedFileFolder.objects.all()
                if current_folder not in all_deleted_folders:
                    deleted_folder = DeletedFileFolder()
                    deleted_folder.folder_name = current_folder
                    deleted_folder.user_id_id = user_id
                    deleted_folder.save()
            excel_file_icon = '<i class="fa fa-file-excel-o" style="font-size:30px;color:#3CB371"></i>'
            pdf_file_icon = '<i class="fa fa-file-pdf-o" style="font-size:30px;color:#DC143C" aria-hidden="true"></i>'
            word_file_icon = '<i class="fa fa-file-word-o" style="font-size:30px;color:#00BFFF;" aria-hidden="true"></i>'
            text_icon = '<i class="fa fa-file-text" style="font-size:30px;color:#808080;" aria-hidden="true"></i>'
            zip_file_icon = '<i class="fa fa-file-archive-o"  style="font-size:30px;color:#FFA500" aria-hidden="true"></i>'
            mp3_icon = '<i class="fas fa-music" style="font-size:30px;color:#FF6600"></i>'
            mp4_icon = '<i class="fa fa-play" style="font-size:30px;color:#FF00CC" aria-hidden="true"></i>'
            json_list = []
            json_list.append(folder_id)
            my_folder = Folder.objects.filter(user_id_id=user_id)
            for item in my_folder:
                product = []
                folder_name = Folder.objects.get(id=item.id)
                all_items = FolderFile.objects.filter(
                    folder_id=item.id).iterator()
                for items in all_items:
                    url = str(items.file_name)
                    a = urlparse(url)
                    file_name = os.path.basename(a.path)
                    name, ext = os.path.splitext(file_name)
                    data = {}
                    if items.file_name:
                        if ext.lower() == '.mp3':
                            data['image'] = ""
                            data['file_name'] = file_name
                            data['file_id'] = items.id
                            data['icon'] = mp3_icon
                        elif ext.lower() == '.mkv' or ext.lower() == '.mp4' or ext.lower() == '.flv' or ext.lower() == '.avi' or ext.lower() == '.wmv' or ext.lower() == '.m4p' or ext.lower() == '.m4v' or ext.lower() == '.mpg' or ext.lower() == '.mp2' or ext.lower() == '.mpeg' or ext.lower() == '.mpe' or ext.lower() == '.nsv' or ext.lower() == '.3gp' or ext.lower() == '.mpv':
                            data['image'] = ""
                            data['file_name'] = file_name
                            data['file_id'] = items.id
                            data['icon'] = mp4_icon
                        else:
                            data['image'] = items.file_name.url
                            data['file_name'] = file_name
                            data['file_id'] = items.id
                            if ext.lower() == '.jpg' or ext.lower() == '.jpeg' or ext.lower() == '.png':
                                data['icon'] = ""
                            elif ext.lower() == '.xlsx':
                                data['icon'] = excel_file_icon
                            elif ext.lower() == '.pdf':
                                data['icon'] = pdf_file_icon
                            elif ext.lower() == '.docx':
                                data['icon'] = word_file_icon
                            elif ext.lower() == '.txt':
                                data['icon'] = text_icon
                            elif ext.lower() == '.zip':
                                data['icon'] = zip_file_icon

                        product.append(data)

                if product:
                    new = {
                        'folder_id': item.id,
                        'user_id': user_id,
                        'folder_name': folder_name.folder_name,
                        'products': product
                    }
                    json_list.append(new)
                else:
                    new = {
                        'folder_id': item.id,
                        'user_id': user_id,
                        'folder_name': folder_name.folder_name,
                    }
                    json_list.append(new)

            data = json.dumps(json_list)
            print(data)
            return HttpResponse(data, content_type='application/json')


# This function is being used to delete the user picture
def deleteuserPic(request):
    response_data = {}
    user_id = request.session['user_id']
    if request.method == "POST":
        user = RegisterUser.objects.get(id=user_id)
        user.profile_pic.delete(save=True)
        response_data['status'] = "success"
        return JsonResponse(response_data)
# Function ends here

# function for share folders for non register users

# @api_view(('POST'))


def Non_register_trash_user_post(request):
    #if request.is_ajax and request.method == "POST" and "user_id" in request.session:
    if request.method == "POST" and "user_id" in request.session:
        loggedin_user_id = request.session['user_id']
        loggedin_user = RegisterUser.objects.get(id=loggedin_user_id)
        user_id_id = loggedin_user.id

        file_id = 0
        folder_name = request.POST['share_folder_id']

        # folder_files = FolderFile.objects.filter(folder_id=folder_id)
        recived_people = request.POST['email']

        email = recived_people
        insert_time = datetime.now(timezone.utc)
        # print(insert_time)
        document_root = ROOT_URL
        token = secrets.token_hex(20)
        link = os.path.join(document_root, 'api/non_registered_trash_download_file', token)
        non_registered_user = NonRegisterFolderFile(
            user_id_id=user_id_id, folder_name=folder_name, file=file_id, link=link, email=email, insert_time=insert_time, token=token)
        non_registered_user.save()

        try:
            sent_mail_template_path = os.path.join(
                settings.BASE_DIR, 'templates/nonregistered_mail_sent.html')

            html_message = loader.render_to_string(
                sent_mail_template_path,
                {
                    'user_name': email,
                    'subject':  'Download the file from below link',
                    'link':  link,
                }
            )
            subject = 'download link'
            from_email = settings.EMAIL_HOST_USER
            message = strip_tags(html_message)
            to = email
            email = EmailMessage(subject, message, from_email, [to])
            email.send()
        except Exception as e:
            print(e)

        response = {
            'status': 200,
            'code': 'successfull',
            'msg': 'email sent successfully',
        }
        return JsonResponse(response)


def non_registered_trash_download_file(request, sharedtoken, *args, **kwargs):

    record = NonRegisterFolderFile.objects.get(token=sharedtoken)
    if record:
        user_id = record.user_id_id
        folder_id = record.folder_id
        file_id = record.file
        link = record.link
        email = record.email

        path = os.path.join(MEDIA_ROOT, str(user_id), str(folder_id))
        destination_path = os.path.join(MEDIA_ROOT, 'shared_files', 'non_registered')
        email_name = email.split("@")[0]
        directory_name = email_name

        link_insert_time = record.insert_time
        server_current_time = datetime.now(timezone.utc)

        dateTimeDifference = server_current_time-link_insert_time
        days, seconds = dateTimeDifference.days, dateTimeDifference.seconds
        total_mins = (dateTimeDifference.days*1440 +
                      dateTimeDifference.seconds/60)
        hours = days * 24 + seconds // 3600
        hours_second = (hours*3600)
        minutes = (seconds % 3600) // 60
        minutes_second = minutes*60
        seconds = seconds % 60
        total_seconds_difference = hours_second + minutes_second + seconds

        hours = timedelta(seconds=86400)

        if dateTimeDifference > hours:
            return HttpResponse("link is exipred")
        else:
            if record.is_downloaded == True:
                return HttpResponse("The link is already used")

            else:

                new_directory_create_path = os.path.join(
                    destination_path, directory_name)
                filenames = []
                if os.path.exists(destination_path):
                    new_directory_create_path_with_record_id = new_directory_create_path + \
                        str(record.id)

                    # print(new_directory_create_path_with_record_id)
                    # sys.exit()

                    os.mkdir(new_directory_create_path_with_record_id)
                    for filepath in pathlib.Path(path).glob('**/*'):

                        shutil.copy(filepath.absolute(
                        ), new_directory_create_path_with_record_id, follow_symlinks=True)
                        filenames.append(filepath.absolute())
                        for fileName in filenames:

                            output_filename = 'downloaded_file.zip'

                            current_zip_path = os.path.join(
                                settings.ZIP_ROOT, str(directory_name + str(record.id)))
                            TARGET_DIRECTORY = current_zip_path
                            ZIPFILE_NAME = directory_name + "." + "zip"

                            def zip_dir(directory, zipname):

                                if os.path.exists(directory):
                                    outZipFile = zipfile.ZipFile(
                                        zipname, 'w', zipfile.ZIP_DEFLATED)

                                    # The root directory within the ZIP file.
                                    rootdir = os.path.basename(directory)

                                    for dirpath, dirnames, filenames in os.walk(directory):
                                        for filename in filenames:

                                            # Write the file named filename to the archive,
                                            # giving it the archive name 'arcname'.
                                            filepath = os.path.join(
                                                dirpath, filename)
                                            parentpath = os.path.relpath(
                                                filepath, directory)
                                            arcname = os.path.join(
                                                rootdir, parentpath)

                                            outZipFile.write(filepath, arcname)

                                    outZipFile.close()

                    zip_dir(TARGET_DIRECTORY, ZIPFILE_NAME)

                    zip_file = open(ZIPFILE_NAME, 'rb')
                    response = HttpResponse(
                        zip_file, content_type='application/force-download')
                    response['Content-Disposition'] = 'attachment; filename="%s"' % 'downloaded_file.zip'
                    record.is_downloaded = True
                    record.save()
                    return response
                else:
                    os.mkdir(destination_path)
    else:
        return HttpResponse("Invalid link")



def Non_register_user_post(request):
    #if request.is_ajax and request.method == "POST" and "user_id" in request.session:
    if request.method == "POST" and "user_id" in request.session:
        loggedin_user_id = request.session['user_id']
        loggedin_user = RegisterUser.objects.get(id=loggedin_user_id)
        user_id_id = loggedin_user.id

        folder_id = request.POST['share_folder_id']
        file_id = 0
        if file_id in request.POST:
            file_id = request.POST['file_id']

        # folder_files = FolderFile.objects.filter(folder_id=folder_id)
        recived_people = request.POST['email']

        email = recived_people
        insert_time = datetime.now(timezone.utc)
        # print(insert_time)
        document_root = ROOT_URL
        token = secrets.token_hex(20)
        link = os.path.join(document_root, 'api/non_registered_download_file', token)
        non_registered_user = NonRegisterFolderFile(
            user_id_id=user_id_id, folder_id=folder_id, file=file_id, link=link, email=email, insert_time=insert_time, token=token)
        non_registered_user.save()

        try:
            sent_mail_template_path = os.path.join(
                settings.BASE_DIR, 'templates/nonregistered_mail_sent.html')

            html_message = loader.render_to_string(
                sent_mail_template_path,
                {
                    'user_name': email,
                    'subject':  'Download the file from below link',
                    'link':  link,
                }
            )
            subject = 'download link'
            from_email = settings.EMAIL_HOST_USER
            message = strip_tags(html_message)
            to = email
            email = EmailMessage(subject, message, from_email, [to])
            email.send()
        except Exception as e:
            print(e)

        response = {
            'status': 200,
            'code': 'successfull',
            'msg': 'email sent successfully',
        }
        return JsonResponse(response)


def non_registered_download_file(request, sharedtoken, *args, **kwargs):

    record = NonRegisterFolderFile.objects.get(token=sharedtoken)
    if record:
        user_id = record.user_id_id
        folder_id = record.folder_id
        file_id = record.file
        link = record.link
        email = record.email

        path = os.path.join(MEDIA_ROOT, str(user_id), str(folder_id))
        destination_path = os.path.join(MEDIA_ROOT, 'shared_files', 'non_registered')
        email_name = email.split("@")[0]
        directory_name = email_name

        link_insert_time = record.insert_time
        server_current_time = datetime.now(timezone.utc)

        dateTimeDifference = server_current_time-link_insert_time
        days, seconds = dateTimeDifference.days, dateTimeDifference.seconds
        total_mins = (dateTimeDifference.days*1440 +
                      dateTimeDifference.seconds/60)
        hours = days * 24 + seconds // 3600
        hours_second = (hours*3600)
        minutes = (seconds % 3600) // 60
        minutes_second = minutes*60
        seconds = seconds % 60
        total_seconds_difference = hours_second + minutes_second + seconds

        hours = timedelta(seconds=86400)

        if dateTimeDifference > hours:
            return HttpResponse("link is exipred")
        else:
            if record.is_downloaded == True:
                return HttpResponse("The link is already used")

            else:

                new_directory_create_path = os.path.join(
                    destination_path, directory_name)
                filenames = []
                if os.path.exists(destination_path):
                    new_directory_create_path_with_record_id = new_directory_create_path + \
                        str(record.id)

                    # print(new_directory_create_path_with_record_id)
                    # sys.exit()

                    os.mkdir(new_directory_create_path_with_record_id)
                    for filepath in pathlib.Path(path).glob('**/*'):

                        shutil.copy(filepath.absolute(
                        ), new_directory_create_path_with_record_id, follow_symlinks=True)
                        filenames.append(filepath.absolute())
                        for fileName in filenames:

                            output_filename = 'downloaded_file.zip'

                            current_zip_path = os.path.join(
                                settings.ZIP_ROOT, str(directory_name + str(record.id)))
                            TARGET_DIRECTORY = current_zip_path
                            ZIPFILE_NAME = directory_name + "." + "zip"

                            def zip_dir(directory, zipname):

                                if os.path.exists(directory):
                                    outZipFile = zipfile.ZipFile(
                                        zipname, 'w', zipfile.ZIP_DEFLATED)

                                    # The root directory within the ZIP file.
                                    rootdir = os.path.basename(directory)

                                    for dirpath, dirnames, filenames in os.walk(directory):
                                        for filename in filenames:

                                            # Write the file named filename to the archive,
                                            # giving it the archive name 'arcname'.
                                            filepath = os.path.join(
                                                dirpath, filename)
                                            parentpath = os.path.relpath(
                                                filepath, directory)
                                            arcname = os.path.join(
                                                rootdir, parentpath)

                                            outZipFile.write(filepath, arcname)

                                    outZipFile.close()

                    zip_dir(TARGET_DIRECTORY, ZIPFILE_NAME)

                    zip_file = open(ZIPFILE_NAME, 'rb')
                    response = HttpResponse(
                        zip_file, content_type='application/force-download')
                    response['Content-Disposition'] = 'attachment; filename="%s"' % 'downloaded_file.zip'
                    record.is_downloaded = True
                    record.save()
                    return response
                else:
                    os.mkdir(destination_path)
    else:
        return HttpResponse("Invalid link")



def non_register_file_share_post(request):

    if request.method != "POST" or "user_id" not in request.session:
        return
    try:
        loggedin_user_id = request.session['user_id']
        loggedin_user = RegisterUser.objects.get(id=loggedin_user_id)
        user_id_id = loggedin_user.id
        folder_id = request.POST['share_folder_id']
        output_str_file_id = request.POST['file_id']
        recived_people = request.POST['email']
        email = recived_people
        share_file_id_list = [output_str_file_id]

        json_share_file_id = json.dumps(share_file_id_list)
        database_record = NonRegisterFolderFile.objects.filter(
            folder_id=folder_id)
        database_record.file = json_share_file_id
        token = secrets.token_hex(20)

        document_root = ROOT_URL
        link = os.path.join(document_root, 'non_registered_download_folder_file', token)
        print(link)
        insert_time_during_file_share_link = datetime.now(timezone.utc)

        non_registered_user_file_share = NonRegisterFolderFile(
            user_id_id=user_id_id, folder_id=folder_id, file=database_record.file, link=link, email=email, insert_time=insert_time_during_file_share_link, token=token)
        non_registered_user_file_share.save()

        sent_mail_template_path = os.path.join(
            settings.BASE_DIR, 'templates/nonregistered_file_mail_sent.html')

        html_message = loader.render_to_string(
            sent_mail_template_path,
            {
                'user_name': email,
                'subject':  'Download the file from below link',
                'link':  link,
             }
        )

        subject = 'download link'
        from_email = settings.EMAIL_HOST_USER
        message = strip_tags(html_message)
        to = email
        email = EmailMessage(subject, message, from_email, [to])
        email.send()
        response = {
            'status': status.HTTP_200_OK,
            'msg': 'Email sent successfully',
        }
        return JsonResponse(response)
    except Exception as e:
        print(e)
        response = {'status': status.HTTP_400_BAD_REQUEST, 'msg': 'Something went wrong!'}

        return JsonResponse(response)


 # define a function for file share inside the folder

class NonRegisterFileShareAPI(APIView):

    permission_classes = [permissions.AllowAny]

    def post(self , request):
        data = request.data
        loggedin_user_id = data.get('user_id_id')
        #loggedin_user_id = request.session['user_id_id']
        loggedin_user = RegisterUser.objects.get(id=loggedin_user_id)
        user_id_id = loggedin_user.id
        print(request.POST)
        # sys.exit()
        folder_id = request.POST['share_folder_id']
        print(folder_id)
        output_str_file_id = request.POST['file_id']
        recived_people = request.POST['email']
        email = recived_people
        share_file_id_list = []
        # print( output_str_file_id)

        share_file_id_list.append(output_str_file_id)
        json_share_file_id = json.dumps(share_file_id_list)
        # print(json_share_file_id)
        database_record = NonRegisterFolderFile.objects.filter(
            folder_id=folder_id)
        database_record.file = json_share_file_id
        # print(database_rec ord.file)

        # database_record_file_update = NonRegisterFolderFile.objects.filter(folder_id= folder_id).update(file=database_record.file)
        token = secrets.token_hex(20)
        print(token)

        document_root = ROOT_URL
        link = document_root + "api/non_registered_download_folder_file/" + token
        insert_time_during_file_share_link = datetime.now(timezone.utc)

        non_registered_user_file_share = NonRegisterFolderFile(
            user_id_id=user_id_id, folder_id=folder_id, file=database_record.file, link=link, email=email, insert_time=insert_time_during_file_share_link, token=token)
        non_registered_user_file_share.save()

        sent_mail_template_path = os.path.join(
            settings.BASE_DIR, 'templates/nonregistered_file_mail_sent.html')

        html_message = loader.render_to_string(
            sent_mail_template_path,
            {
                'user_name': email,
                'subject':  'Download the file from below link',
                'link':  link,

            }
        )

        subject = 'download link'
        from_email = settings.EMAIL_HOST_USER
        message = strip_tags(html_message)
        to = email
        print(subject)
        print(from_email)
        print(to)
        print(message)
        email = EmailMessage(subject, message, from_email, [to])
        email.send()
        response = {
            'status': 200,
            'code': 'successfull',
            'msg': 'email sent successfully',
        }
        return JsonResponse(response)


# function for download file inside a particular folder


def non_registered_download_folder_file(request, sharedtoken, *args, **kwargs):
    found_all_filenames = []
    record = NonRegisterFolderFile.objects.get(token=sharedtoken)
    if record:
        if record:
            user_id = record.user_id_id
            # print(user_id)
            folder_id = record.folder_id
            # print(folder_id_ids)
            file_id = record.file
            file_id = file_id.split(',')
            print(file_id)
            # print(*file_id, sep=',')
            for id in (file_id):
                id = id.strip('[]')
                print(id)
                id = id.strip('""')
                print(id)
                id = int(id)
                # print(id)
                filename = FolderFile.objects.filter(
                    id=id).values_list('only_file_name', flat=True)
                print("database query")
                print(filename.query)
                for file in filename:
                    # print(type(file))
                    found_all_filenames.append(file)
                    # print(found_all_filenames)
                    # print('.'.join(str(x) for x in all_filenames))
                    found_all_filenames_in_string = '\n'.join(
                        str(x) for x in found_all_filenames)
                print(found_all_filenames_in_string)
                print("after appending in a list")
                print(found_all_filenames)

        link = record.link

        email = record.email
        path = MEDIA_ROOT + "/" + str(user_id) + "/" + str(folder_id)

        destination_path = MEDIA_ROOT + "/" + \
            "shared_files" + "/" + "non_registered" + "/"
        email_name = email.split("@")[0]
        directory_name = email_name

        link_insert_time = record.insert_time
        print(link_insert_time)

        server_current_time = datetime.now(timezone.utc)
        print(server_current_time)

        dateTimeDifference = server_current_time-link_insert_time
        days, seconds = dateTimeDifference.days, dateTimeDifference.seconds
        total_mins = (dateTimeDifference.days*1440 +
                      dateTimeDifference.seconds/60)
        hours = days * 24 + seconds // 3600
        hours_second = (hours*3600)
        minutes = (seconds % 3600) // 60
        minutes_second = minutes*60
        seconds = seconds % 60
        total_seconds_difference = hours_second + minutes_second + seconds

        hours = timedelta(seconds=86400)
        # hours = timedelta(seconds=30)

        print(total_seconds_difference)
        print(hours)

        if dateTimeDifference > hours:
            print("link is exipred")
            return HttpResponse("link is exipred")
        else:
            if record.is_downloaded == True:
                print("The link is already used")
                return HttpResponse("The link is already used")

            else:
                print("hi")

                new_directory_create_path = os.path.join(
                    destination_path, directory_name)

                print(destination_path)
                if os.path.exists(destination_path):
                    print("exist")
                    new_directory_create_path_with_record_id = new_directory_create_path + \
                        str(record.id)
                    os.mkdir(new_directory_create_path_with_record_id)
                    paths = pathlib.Path(path).glob('**/*')
                    for filepath in pathlib.Path(path).glob('**/*'):
                        directory_file_name = os.path.basename(
                            filepath.absolute())
                        print(filepath.absolute())
                        print(directory_file_name)
                        print(found_all_filenames)
                        filenames = []
                        if directory_file_name in found_all_filenames:
                            for file in found_all_filenames:
                                print(new_directory_create_path_with_record_id)
                                shutil.copy(filepath.absolute(
                                ), new_directory_create_path_with_record_id, follow_symlinks=True)
                                filenames.append(filepath.absolute())
                            print(filenames)
                        # sys.exit()
                        #output_filename = 'downloaded_file.zip'
                        for fileName in filenames:
                            current_zip_path = os.path.join(
                                settings.ZIP_ROOT, str(directory_name + str(record.id)))
                            TARGET_DIRECTORY = current_zip_path
                            print(TARGET_DIRECTORY)
                            ZIPFILE_NAME = directory_name + "." + "zip"
                            def zip_dir(directory, zipname):
                                if os.path.exists(directory):
                                    outZipFile = zipfile.ZipFile(
                                        zipname, 'w', zipfile.ZIP_DEFLATED)

                                    # The root directory within the ZIP file.
                                    rootdir = os.path.basename(directory)

                                    for dirpath, dirnames, filenames in os.walk(directory):
                                        for filename in filenames:
                                            # Write the file named filename to the archive,
                                            # giving it the archive name 'arcname'.
                                            filepath = os.path.join(
                                                dirpath, filename)
                                            parentpath = os.path.relpath(
                                                filepath, directory)
                                            arcname = os.path.join(
                                                rootdir, parentpath)
                                            outZipFile.write(filepath, arcname)
                                    outZipFile.close()
                    zip_dir(TARGET_DIRECTORY, ZIPFILE_NAME)
                    zip_file = open(ZIPFILE_NAME, 'rb')
                    response = HttpResponse(
                        zip_file, content_type='application/force-download')
                    response['Content-Disposition'] = 'attachment; filename="%s"' % 'downloaded_file.zip'
                    record.is_downloaded = True
                    record.save()
                    return response
                else:
                    os.mkdir(destination_path)
    else:
        return HttpResponse("Invalid link")

# def non_registered_download_folder_file(request,sharedtoken,*args,**kwargs):
#     found_all_filenames = []
#     record = NonRegisterFolderFile.objects.get(token= sharedtoken)
#     # print(record)
#     if record:
#         user_id= record.user_id_id
#         # print(user_id)
#         folder_id = record.folder_id


#         # print(folder_id_ids)

#         file_id = record.file
#         file_id = file_id.split(',')
#         print(file_id)
#         # print(*file_id, sep=',')
#         for id in (file_id):

#             id = id.strip('[]')
#             print(id)

#             id = id.strip('""')
#             print(id)


#             id = int(id)
#             # print(id)
#             filename = FolderFile.objects.filter(id=id).values_list('only_file_name', flat=True)
#             print("database query")
#             print(filename)
#             for file in filename:
#                 # print(type(file))
#                 found_all_filenames.append(file)
#                 # print(found_all_filenames)
#                 # print('.'.join(str(x) for x in all_filenames))
#                 found_all_filenames_in_string = '\n'.join(str(x) for x in found_all_filenames)
#             print(found_all_filenames_in_string)
#             print("after appending in a list")
#             print(found_all_filenames)
#             # sys.exit()


#         link = record.link
#         # print(link)
#         email = record.email
#         # print(email)
#         path = MEDIA_ROOT + "/" + str(user_id) + "/" + str(folder_id) + "/"
#         destination_path = MEDIA_ROOT + "/" + "shared_files" + "/" + "non_registered" + "/"
#         email_name = email.split("@")[0]
#         directory_name = email_name
#         link_insert_time = record.insert_time
#         print(link_insert_time)
#         server_current_time = datetime.now(timezone.utc)
#         print(server_current_time)
#         dateTimeDifference = server_current_time-link_insert_time
#         days, seconds = dateTimeDifference.days, dateTimeDifference.seconds
#         total_mins = (dateTimeDifference.days*1440 + dateTimeDifference.seconds/60)
#         hours = days * 24 + seconds // 3600
#         hours_second = (hours*3600)
#         minutes = (seconds % 3600) // 60
#         minutes_second = minutes*60
#         seconds = seconds % 60
#         total_seconds_difference =hours_second + minutes_second + seconds
#         hours = timedelta(seconds=86400)
#         # hours = timedelta(seconds=30)
#         print(total_seconds_difference)
#         print(hours)
#         if dateTimeDifference > hours :
#             print("link is exipred")
#             return HttpResponse("link is exipred")
#         else:
#             if record.is_downloaded == True:
#                 print("The link is already used")
#                 return HttpResponse("The link is already used")
#             else:
#                 new_directory_create_path = os.path.join(destination_path, directory_name)
#                 filenames = []
#                 if os.path.exists(destination_path):
#                     new_directory_create_path_with_record_id = new_directory_create_path + str(record.id)
#                     # if os.path.exists(new_directory_create_path_with_record_id):
#                     os.mkdir(new_directory_create_path_with_record_id)
#                     for filepath in pathlib.Path(path).glob('**/*'):
#                         print(filepath.absolute())
#                         directory_file_name = os.path.basename(filepath.absolute())
#                         print("get all base name from absolute")
#                         # print(directory_file_name.split())
#                         # sys.exit()
#                         # if directory_file_name in found_all_filenames:
#                         #     print("after matching with list file names")
#                         #     print(directory_file_name)
#                             # sys.exit()
#                         # print(new_directory_create_path_with_record_id)
#                         shutil.copy(filepath.absolute(), new_directory_create_path_with_record_id, follow_symlinks=True)
#                         filenames.append(filepath.absolute())
#                         for fileName in filenames:
#                             output_filename = 'downloaded_file.zip'
#                             current_zip_path = os.path.join(settings.ZIP_ROOT,str(directory_name + str(record.id)))
#                             TARGET_DIRECTORY = current_zip_path
#                             print(TARGET_DIRECTORY)
#                             ZIPFILE_NAME = directory_name + "." + "zip"
#                             def zip_dir(directory, zipname):
#                                 if os.path.exists(directory):
#                                     outZipFile = zipfile.ZipFile(zipname, 'w', zipfile.ZIP_DEFLATED)
#                                     # The root directory within the ZIP file.
#                                     rootdir = os.path.basename(directory)
#                                     for dirpath, dirnames, filenames in os.walk(directory):
#                                         for filename in filenames:
#                                             # Write the file named filename to the archive,
#                                             # giving it the archive name 'arcname'.
#                                             filepath   = os.path.join(dirpath, filename)
#                                             parentpath = os.path.relpath(filepath, directory)
#                                             arcname    = os.path.join(rootdir, parentpath)
#                                             outZipFile.write(filepath, arcname)
#                                     outZipFile.close()
#                         zip_dir(TARGET_DIRECTORY, ZIPFILE_NAME)
#                         zip_file = open(ZIPFILE_NAME, 'rb')
#                         response = HttpResponse(zip_file, content_type='application/force-download')
#                         response['Content-Disposition'] = 'attachment; filename="%s"' % 'downloaded_file.zip'
#                         record.is_downloaded = True
#                         record.save()
#                         return response
#                         # else:
#                         #     print("no matching found")
#                 else:
#                     os.mkdir(destination_path)
#     else:
#         return HttpResponse("Invalid link")
    # return HttpResponse("download successfull all abd")

# to search any file inside folder
def search_files_inside_folders(request, *args, **kwargs):
    if request.is_ajax and request.method == "POST" and "user_id" in request.session:
        loggedin_user_id = request.session['user_id']
        loggedin_user = RegisterUser.objects.get(id=loggedin_user_id)
        user_id_id = loggedin_user.id

        # print(request.POST)
        # sys.exit()
        search_key = request.POST['search_key']
        serach_folder_id = request.POST['serach_folder_id']

        all_filenames = []
        found_file = []
        filename = FolderFile.objects.filter(
            folder_id=serach_folder_id).values_list('only_file_name', flat=True)

        for file in filename:
            all_filenames.append(file)
            # print('.'.join(str(x) for x in all_filenames))
            all_filenames_in_string = '.'.join(str(x) for x in all_filenames)

        folder_path = MEDIA_ROOT + "/" + \
            str(user_id_id) + "/" + str(serach_folder_id) + "/"
        if os.path.exists(folder_path):
            if search_key in all_filenames_in_string:
                print(all_filenames_in_string)
                found_file.append(search_key)
                print(found_file)

                response = {
                    'status': 200,
                    'code': 'successfull',
                    'msg': found_file,
                    'filename': all_filenames_in_string,
                     'folderid': serach_folder_id,
                }
                return JsonResponse(response)

            else:
                response_invalid = {
                    'status': 501,
                    'code': 'unsuccessfull',
                    'msg': 'No matches found',
                }
        else:
            response = {
                'status': 'error',
                'code': status.HTTP_400_BAD_REQUEST,
                'message': 'folder path does not exist'
            }
    else:
        response = {
            'status': 'error',
            'code': status.HTTP_400_BAD_REQUEST,
            'message': 'please login'
        }

    return JsonResponse(response)


#

# def chart_data(request):
#     user_id = request.session['user_id']
#     total_folder_fr_current_user = Folder.objects.filter(user_id_id = user_id).count()
#     total_files_fr_current_user = FolderFile.objects.filter(user_id_id = user_id).count()

#     new = [{'name':'Capacity',
#             'y': 50,
#             },
#             {'name':'completed',
#             'y': 50,
#             }]
#     print(new)

#     chart = {
 #         'chart': {'type': 'pie'},
#         'title': {'text': 'Titanic Survivors by Ticket Class'},
#         'series': [{
#             'name': 'Embarkation Port',
#             'data': [{'name':'Capacity',
#             'y': 50,
#             },
#             {'name':'completed',
#             'y': 50,
#             }]
#         }]
#     }

#     return JsonResponse(chart)


# sear folder test function
def search_folderr(request):
    user_id = request.session['user_id']
    print(user_id)
    data = request.POST
    print(data['folder_text'])
    folder_file = FolderFile.objects.filter(Q(folder_id = 1) | Q(user_id_id = user_id))
    #files=
    # folder_file = FolderFile.objects.filter(
    #         folder_id=data['folder_text']).values_list('only_file_name', flat=True)
    #print(type(folder_file))
    #print(folder_file)
    product = []
    for item in folder_file:
        print(item.id,item.file_name,item.only_file_name)#filename
        # product.append({
        # 'image':file_name, 'file_name': item.only_file_name, 'file_id': item.id, 'type': 'file', 'icon':""
        # })
    #print(product)
    return HttpResponse(data['folder_text'], content_type="text/plain")
    excel_file_icon = '<i class="fa fa-file-excel-o" style="font-size:30px;color:#3CB371"></i>'
    pdf_file_icon = '<i class="fa fa-file-pdf-o" style="font-size:30px;color:#DC143C" aria-hidden="true"></i>'
    word_file_icon = '<i class="fa fa-file-word-o" style="font-size:30px;color:#00BFFF;" aria-hidden="true"></i>'
    text_icon = '<i class="fa fa-file-text" style="font-size:30px;color:#808080;" aria-hidden="true"></i>'
    zip_file_icon = '<i class="fa fa-file-archive-o"  style="font-size:30px;color:#FFA500" aria-hidden="true"></i>'
    mp3_icon = '<i class="fas fa-music" style="font-size:30px;color:#FF6600"></i>'
    mp4_icon = '<i class="fa fa-play" style="font-size:30px;color:#FF00CC" aria-hidden="true"></i>'
    file_icon = '<i class="fa fa-file" style="font-size:30px;" aria-hidden="true"></i>'
    result = []
    print(request.POST)
    # sys.exit()
    folder_name_text = data.get('folder_text')
    if folder_name_text != "":
        folders = Folder.objects.filter(
            Q(folder_name__icontains=folder_name_text), user_id=user_id)
    else:
        folders = Folder.objects.filter(user_id=user_id)
    for item in folders:
        product = []
        folder_name = Folder.objects.get(id=item.id)
        all_items = FolderFile.objects.filter(folder_id=item.id).iterator()
        all_item_count = FolderFile.objects.filter(folder_id=item.id).count()
        for_size = FolderFile.objects.filter(folder_id=item.id)
        full_size = 0
        for files in for_size:
            if files.file_name:
                full_path = os.path.join(
                    settings.MEDIA_ROOT, str(files.file_name))
                if os.path.isfile(full_path):
                    size = os.path.getsize(str(full_path))
                    full_size += size
        if full_size > 1073741824:
            real_size = str(round(int(full_size)/1073741824)) + " GB"
        elif full_size > 1048576:
            real_size = str(round(int(full_size)/1048576)) + " MB"
        else:
            real_size = str(round(int(full_size)/1024)) + " KB"
        for items in all_items:
            url = str(items.file_name)
            a = urlparse(url)
            file_name = os.path.basename(a.path)
            name, ext = os.path.splitext(file_name)
            data = {}
            if items.file_name:
                if ext.lower() == '.mp3':
                    data['image'] = items.file_name.url
                    data['file_name'] = file_name
                    data['file_id'] = items.id
                    data['icon'] = mp3_icon
                elif ext.lower() == '.mkv' or ext.lower() == '.mp4' or ext.lower() == '.flv' or ext.lower() == '.avi' or ext.lower() == '.wmv' or ext.lower() == '.m4p' or ext.lower() == '.m4v' or ext.lower() == '.mpg' or ext.lower() == '.mp2' or ext.lower() == '.mpeg' or ext.lower() == '.mpe' or ext.lower() == '.nsv' or ext.lower() == '.3gp' or ext.lower() == '.mpv':
                    data['image'] = items.file_name.url
                    data['file_name'] = file_name
                    data['file_id'] = items.id
                    data['icon'] = mp4_icon
                else:
                    data['image'] = items.file_name.url
                    data['file_name'] = file_name
                    data['file_id'] = items.id
                    if ext.lower() == '.jpg' or ext.lower() == '.jpeg' or ext.lower() == '.png':
                        data['icon'] = ""
                    elif ext.lower() == '.xlsx':
                        data['icon'] = excel_file_icon
                    elif ext.lower() == '.pdf':
                        data['icon'] = pdf_file_icon
                    elif ext.lower() == '.docx':
                        data['icon'] = word_file_icon
                    elif ext.lower() == '.txt':
                        data['icon'] = text_icon
                    elif ext.lower() == '.zip':
                        data['icon'] = zip_file_icon
                    else:
                        data['icon'] = file_icon

                product.append(data)

        if product:
            new = {
                'folder_id': item.id,
                'user_id': user_id,
                'folder_name': folder_name.folder_name,
                'products': product,
                'count': all_item_count,
                'real_size': real_size
            }
            result.append(new)
        else:
            new = {
                'folder_id': item.id,
                'user_id': user_id,
                'folder_name': folder_name.folder_name,
                'count': '0'
            }
            result.append(new)
            print(result)
    return JsonResponse(response)
    return render(request, 'folder_search_result.html', {'result': result})


class givefeedback(APIView):
    """
    this classed used to give feedback
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        print("feedback")

        #user_id = request.session['user_id']
        data = request.data
        feedmail = data.get('feedmail')

        feedtext = data.get('feedtext')
        feedback = Feedback(email=feedmail, feedback=feedtext)
        feedback.save()
        response = {
            'status': 'Success',
        }

        # print(response)
        return JsonResponse(response)

        # return render(request, 'feedback.html')
        # return render(request, 'change_pass.html')

class TrashRetriveAPI(APIView):

    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data
        user_id = data.get('user_id')
        #user_id = request.session['user_id']
        print(request.POST)
        trash_ids = request.POST['trash_files_ids']
        trash_files_ids = trash_ids.split(",")
        trash_files_ids_string = ''.join(trash_files_ids)
        trash_files_ids_int = int(trash_files_ids_string)
        # print(type(trash_files_ids_int))
        # sys.exit()
        filename = DeletedFileFolder.objects.filter(
            id=trash_files_ids_int).values_list('file_name', flat=True)
        filename_string = ''.join(filename)
        folder_name = DeletedFileFolder.objects.filter(
            id=trash_files_ids_int).values_list('folder_name', flat=True)
        folder_name_string = ''.join(folder_name)
        print(folder_name_string)
        # sys.exit()
        record = Folder.objects.get(folder_name=folder_name_string)

        folder_id = record.id
        record_filefolder = FolderFile.objects.get(folder_id=folder_id)
        record_filefolder.file_name = filename_string
        print(record_filefolder.file_name)
        sys.exit()
        # record.save()
        # print(type(filename))
        # filename_list = [str(file_name ) for file_name in filename]
        # # print(type(filename_list))
        # filename_string = ''.join(filename_list)
        # print(filename_string)

        # if os.path.exists(filename_string):
        #     # how to get back original file?
        #     extension = os.path.splitext(filename_string)[1]
        #     print(extension)
        #     if extension == ".jpg":
        #         basename = os.path.basename(filename_string)
        #         print(basename)

        #         filename_path = os.path.dirname(filename_string)
        #         print(filename_path)

        #         img = Image.open(os.path.join(filename_path, basename)) # images are color images
        #         img.show(basename+'.jpeg')

        #     elif extension == ".png":
        #         basename = os.path.basename(filename_string)
        #         print(basename)

        #         filename_path = os.path.dirname(filename_string)
        #         print(filename_path)
        #         img = Image.open(os.path.join(filename_path, basename)) # images are color images

        #         img.show(basename+'.png')

        #     elif extension == ".pdf":
        #         basename = os.path.basename(filename_string)
        #         print(basename)

        #         filename_path = os.path.dirname(filename_string)
        #         print(filename_path)
        #         directory_path_with_name = os.path.join(filename_path, basename)

        #         pdf_file = open(directory_path_with_name,'rb')

        #         read_pdf = PyPDF2.PdfFileReader(pdf_file)
        #         # print(inputpdf)
        #         number_of_pages = read_pdf.getNumPages()
        #         page = read_pdf.getPage(0)
        #         page_content = page.extractText()
        #         print(page_content)
        #         # writer = PyPDF2.PdfFileWriter()
        #         # with open(basename, 'wb') as output:
        #         #     writer.write(output)
        #         output = PdfFileWriter()
        #         # add the "watermark" (which is the new pdf) on the existing page
        #         page = existing_pdf.getPage(0)
        #         page.mergePage(new_pdf.getPage(0))
        #         output.addPage(page)
        #         # finally, write "output" to a real file
        #         outputStream = open(basename, "wb")
        #         output.write(outputStream)
        #         outputStream.close()
        #     else:
        #         directory_path_with_name = os.path.join(filename_path, basename)
        #         os.mkdir(directory_path_with_name)

        # sys.exit()
        # for item in trash_files_ids:
        #     trash_item = DeletedFileFolder.objects.get(id=item)
        #     if trash_item.shared == False:
        #         if '/' in str(os):
        #             full_path = os.path.join(settings.MEDIA_ROOT,str(trash_item.file_name))
        #             os.remove(full_path)
        #         else:
        #             trash_path = trash_item.file_name
        #             os.remove(str(trash_path))
        #         trash_item.delete()
        #     else:
        #         trash_item.delete()
        # OFFSET = request.session['trash_offset']
        # END = request.session['trash_end']
        # json_list = []
        # # json_list.append(starting_number)
        # new_delete_files = DeletedFileFolder.objects.filter(user_id_id = user_id).order_by('-id')[OFFSET:END]
        # for item in new_delete_files:
        #     url =str(item.file_name)
        #     a = urlparse(url)
        #     file_name = os.path.basename(a.path)
        #     json_list.append({
        #         'folder_name':item.folder_name,'file':item.file_name.url,'file_name':file_name,'file_id':item.id
        #     })

        # data = json.dumps(json_list)
        return HttpResponse("hello")

from cryptography.fernet import Fernet
#test new features
def handle_uploaded_file2(file):#receive file name to be encrypted and saved
    # key generation{{{{{{{{{{{{{{{one time process}}}}}}}}}}}}}}}
    #key = Fernet.generate_key()

    # string the key in a file
    #with open('filekey.key', 'wb') as filekey:
        #filekey.write(key)

    # opening the key
    with open('filekey.key', 'rb') as filekey:
        key = filekey.read()

    # using the generated key
    fernet = Fernet(key)
    print("file name",file)
    filename=str(file)
    with open('media/enc_files/'+filename, 'wb+') as destination:
        for chunk in file.chunks():
            destination.write(chunk)

    # opening the original file to encrypt
    with open('media/enc_files/'+filename, 'rb') as file:
        original = file.read()

    # encrypting the file
    encrypted = fernet.encrypt(original)

    # opening the file in write mode and
    # writing the encrypted data
    with open('media/enc_files/'+filename, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

def file_decript(n_file):
    # opening the key
    with open('filekey.key', 'rb') as filekey:
        key = filekey.read()
    # using the key
    fernet = Fernet(key)

# opening the encrypted file
    with open('media/enc_files/'+n_file, 'rb') as enc_file:
        encrypted = enc_file.read()

# decrypting the file
        decrypted = fernet.decrypt(encrypted)

# opening the file in write mode and
# writing the decrypted data
    with open('media/tem_files/'+n_file, 'wb') as dec_file:
        dec_file.write(decrypted)


def fileupload2(request):#upload file in a particular folder and add database entries
    file_name=str(request.FILES['myfile']) # this is my file
    handle_uploaded_file2(request.FILES['myfile'])
    #add to database
    user = request.session['user_id']
    #UploadFiles2.objects.create(user_id=user,file_name=file_name,file_ext='ext' )
    #return redirect(request.META['HTTP_REFERER'])
    return JsonResponse({'status':'success'})

def fileshare2(request):
    pass

def filedelete2(request,file):
    #UploadFiles2.objects.filter(file=file).delete()
    return redirect(request.META['HTTP_REFERER'])

def filedownload2(request,file):# accept file id as parameter - get the file name - decode the file and serve it
    print(file)
    filen=UploadFiles2.objects.filter(file=file).values('file_name')
    n_file=(str(filen[0]['file_name']))
    #(courses[0]['course_code'])
    #print("############")

    #return JsonResponse({'status':'success'})
    file_decript(n_file)
    fsock = open('media/tem_files/'+n_file, 'rb')
    response =  HttpResponse(fsock, content_type='application/octet-stream')
    response['Content-Disposition'] = "attachment; filename={}".format(n_file)
    return response


class FileDownloadAPIView(APIView):

    permission_classes = [permissions.AllowAny]

    def post(self,request):

        serializer = FileDownloadSerializer(data=request.DATA)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response({'key': 'value'}, status=status.HTTP_200_OK)


class ExpiringTokenAuthentication(TokenAuthentication):
    """
    Expiring token for mobile and desktop clients.
    It expires every {n} hrs requiring client to supply valid username
    and password for new one to be created.
    """

    model = ShareFile

    def authenticate_credentials(self, key, request=None):
        models = self.get_model()

        try:
            token = models.objects.select_related("user").get(key=key)
        except models.DoesNotExist:
            raise AuthenticationFailed(
                {"error": "Invalid or Inactive Token", "is_authenticated": False}
            )

        if not token.user.is_active:
            raise AuthenticationFailed(
                {"error": "Invalid user", "is_authenticated": False}
            )

        utc_now = timezone.now()
        utc_now = utc_now.replace(tzinfo=pytz.utc)

        if token.created < utc_now - settings.TOKEN_TTL:
            raise AuthenticationFailed(
                {"error": "Token has expired", "is_authenticated": False}
            )
        return token.user, token

class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = RegisterUser
    permission_classes = ()

    def get_object(self, queryset=None):
        obj = self.request.user_id
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):

    email_plaintext_message = "{}?token={}".format(reverse('password_reset:reset-password-request'), reset_password_token.key)

    send_mail(
        "Password Reset for {title}".format(title="Some website title"),
        email_plaintext_message,
        "noreply@somehost.local",
        [reset_password_token.user.email]
    )


class PiecharAPI(APIView):

    permission_classes = [permissions.AllowAny]

    def get(self, request):
        file_name = request.data.get('file_name')
        user_id = request.data.get('user_id')
        name = FolderFile.objects.all().filter(file_name=file_name)
        graph_data_outer = []
        all_current_files = FolderFile.objects.filter(user_id_id=user_id)
        file_type = []
        for item in all_current_files:
            if item.file_name:
                filepath = os.path.join(
                    settings.MEDIA_ROOT, str(item.file_name))
                name, extension = os.path.splitext(filepath)
                file_type.append(extension)

        type_count = {x: file_type.count(x) for x in file_type}
        if len(type_count) != 0:
            for key, value in type_count.items():
                graph_data_outer.append({
                    'name': str(key), 'y': value, 'selected': 'true'
                })
        else:
            graph_data_outer.append({
                'name': 'capacity', 'y': 100
            })
        return Response(graph_data_outer)


class TrashlistAPI(APIView):

    permission_classes = [permissions.AllowAny]

    def get(self, request):
        trash = DeletedFileFolder.objects.all()
        serializer = TrashSerializer(trash, many=True)
        return Response(serializer.data)

class FileListAPI(APIView):

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        folder_id = data.get('folder_id')
        folderfiles = FolderFile.objects.all().filter(folder_id=folder_id)
        serializer = FolderFileSerializer(folderfiles, many=True)
        print(serializer)
        return Response(serializer.data)


class FileCountAPI(APIView):

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        folder_id = data.get('folder_id')
        all_item_count = FolderFile.objects.filter(
                folder_id=folder_id).count()
        print("ALL", all_item_count)
        return Response(all_item_count)

"""
def share(request):
    if request.method == 'POST':
        file = request.POST.get('filedata')
        folder_name = request.META.get('folder_name')
        targetUser = request.META.get('share_people_ids')
        #user = request.user
        user = RegisterUser.objects.filter(user_id = targetUser)[0]
        root_folder = Folder.objects.filter(user_id=user)[0]
        destination = str(root_folder.name)
    result = {
        'reload': '200'
    }
    return JsonResponse(result)
    def post(self, request):
        #folder_name = self.request.get("folder_name")
        data = request.data
        print("data", data)
        user_id = data.get('user_id')
        folders = Folder.objects.all().filter(user_id_id=user_id)
        serializer = FolderSerializer(folders, many=True)
        print(serializer)
        return Response(serializer.data)
"""

class FileExistAPI(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        data = request.data
        user_id = data.get('user_id_id')
        folder_id = data.get('folder_id')
        file_name = data.get('file_name')
        file_data = FolderFile.objects.filter(folder_id=folder_id, user_id=user_id)
        val = file_name
        if file_name in file_data:
            print("File is already exist")
            while(FolderFile.objects.filter(only_file_name=val, user_id_id=user_id).exists()):
                res =  [re.findall(r'(\w+?)(\d+)', val)[0]]
                number = res[0][1]
                same_name = res[0][0]
                val = str(same_name)+str(int(number)+1)
                file_name = val
        else:
            # val += str(1)
            # print(val)
            file_name = val

        response = {
            'status': "OK",
            'only_file_name': file_name
        }
        return Response(response)


def CheckIfFileExists():
        data = request.data
        user_id = data.get('user_id_id')
        folder_id = data.get('folder_id')
        file_name = data.get('file_name')
        file_data = FolderFile.objects.filter(folder_id=folder_id, user_id_id=user_id)
        #val = file_name
        if file_name in file_data:
            return True
        else:
            return False


def trash_retrieve(request, *args, **kwargs):
    user_id = request.session['user_id']
    print(request.POST)

    # sys.exit()
    trash_ids = request.POST['trash_files_ids']
    trash_files_ids = trash_ids.split(",")
    trash_files_ids_string = ''.join(trash_files_ids)
    trash_files_ids_int = int(trash_files_ids_string)
    # print(type(trash_files_ids_int))
    # sys.exit()
    filename = DeletedFileFolder.objects.filter(
        id=trash_files_ids_int).values_list('file_name', flat=True)
    filename_string = ''.join(filename)
    folder_name = DeletedFileFolder.objects.filter(
        id=trash_files_ids_int).values_list('folder_name', flat=True)
    folder_name_string = ''.join(folder_name)
    print(folder_name_string)
    # sys.exit()
    record = Folder.objects.get(folder_name=folder_name_string)

    folder_id = record.id
    record_filefolder = FolderFile.objects.get(folder_id=folder_id)
    record_filefolder.file_name = filename_string
    print(record_filefolder.file_name)
    sys.exit()
    # record.save()
    # print(type(filename))
    # filename_list = [str(file_name) for file_name in filename]
    # # print(type(filename_list))
    # filename_string = ''.join(filename_list)
    # print(filename_string)

    # if os.path.exists(filename_string):
    #     # how to get back original file?
    #     extension = os.path.splitext(filename_string)[1]
    #     print(extension)
    #     if extension == ".jpg":
    #         basename = os.path.basename(filename_string)
    #         print(basename)

    #         filename_path = os.path.dirname(filename_string)
    #         print(filename_path)

    #         img = Image.open(os.path.join(filename_path, basename)) # images are color images
    #         img.show(basename+'.jpeg')

    #     elif extension == ".png":
    #         basename = os.path.basename(filename_string)
    #         print(basename)

    #         filename_path = os.path.dirname(filename_string)
    #         print(filename_path)
    #         img = Image.open(os.path.join(filename_path, basename)) # images are color images

    #         img.show(basename+'.png')

    #     elif extension == ".pdf":
    #         basename = os.path.basename(filename_string)
    #         print(basename)

    #         filename_path = os.path.dirname(filename_string)
    #         print(filename_path)
    #         directory_path_with_name = os.path.join(filename_path, basename)

    #         pdf_file = open(directory_path_with_name,'rb')

    #         read_pdf = PyPDF2.PdfFileReader(pdf_file)
    #         # print(inputpdf)
    #         number_of_pages = read_pdf.getNumPages()
    #         page = read_pdf.getPage(0)
    #         page_content = page.extractText()
    #         print(page_content)
    #         # writer = PyPDF2.PdfFileWriter()
    #         # with open(basename, 'wb') as output:
    #         #     writer.write(output)
    #         output = PdfFileWriter()
    #         # add the "watermark" (which is the new pdf) on the existing page
    #         page = existing_pdf.getPage(0)
    #         page.mergePage(new_pdf.getPage(0))
    #         output.addPage(page)
    #         # finally, write "output" to a real file
    #         outputStream = open(basename, "wb")
    #         output.write(outputStream)
    #         outputStream.close()
    #     else:
    #         directory_path_with_name = os.path.join(filename_path, basename)
    #         os.mkdir(directory_path_with_name)

    # sys.exit()
    # for item in trash_files_ids:
    #     trash_item = DeletedFileFolder.objects.get(id=item)
    #     if trash_item.shared == False:
    #         if '/' in str(os):
    #             full_path = os.path.join(settings.MEDIA_ROOT,str(trash_item.file_name))
    #             os.remove(full_path)
    #         else:
    #             trash_path = trash_item.file_name
    #             os.remove(str(trash_path))
    #         trash_item.delete()
    #     else:
    #         trash_item.delete()
    # OFFSET = request.session['trash_offset']
    # END = request.session['trash_end']
    # json_list = []
    # # json_list.append(starting_number)
    # new_delete_files = DeletedFileFolder.objects.filter(user_id_id = user_id).order_by('-id')[OFFSET:END]
    # for item in new_delete_files:
    #     url =str(item.file_name)
    #     a = urlparse(url)
    #     file_name = os.path.basename(a.path)
    #     json_list.append({
    #         'folder_name':item.folder_name,'file':item.file_name.url,'file_name':file_name,'file_id':item.id
    #     })

    # data = json.dumps(json_list)
    return HttpResponse("hello")

class DeleteTrashItemView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data
        user_id = request.session['user_id']
        files_ids = data.get('detete_files_ids')
        if files_ids:
            files_ids = files_ids.split(",")
            for file_id in files_ids:
                has_file = DeletedFileFolder.objects.get(id=file_id, is_deleted=False)
                if has_file:
                    has_file.is_deleted = True
                    has_file.save()

        json_list = []
        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')

class RestoreTrashItemView(APIView):

    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data
        user_id = request.session['user_id']
        files_ids = data.get('detete_files_ids')
        delete_files_ids = files_ids.split(",")
        for item_id in delete_files_ids:
            current_file = DeletedFileFolder.objects.get(id=int(item_id))
            user_id = current_file.user_id_id
            login_user = RegisterUser.objects.get(id=user_id)
            folder_name = current_file.id
            folder = DeletedFileFolder.objects.get(id=folder_name)
            folder_name = folder.folder_name
            current_file_name = current_file.file_name
            all_folders = Folder.objects.filter(user_id=user_id).values('folder_name')
            # current_file_path = os.path.join(settings.MEDIA_ROOT, str(user_id), str(current_file_name))
            current_file_path = os.path.join(settings.MEDIA_ROOT, str(current_file_name))

            fsize = os.stat(current_file_path)
            ori_fsizekb = round(fsize.st_size / 1024)
            login_user.uploaded_size = int(
                login_user.uploaded_size) - int(ori_fsizekb)
            login_user.save()
            url = str(current_file_name)
            a = urlparse(url)
            file_name = os.path.basename(a.path)
            folders = Folder.objects.filter(folder_name=folder_name)
            if folders.exists():
                folder_name_exist = folders.values()
                folder_id_exits = list(folder_name_exist)[0]
                folderid = folder_id_exits['id']
            else:
                user = RegisterUser.objects.filter(id=user_id)
                user_val = user.values()
                user_id_exits = list(user_val)[0]
                u_id = user_id_exits['token']
                url = 'http://127.0.0.1:8000/api/create_folder/'
                data = {
                    'create_user_id':u_id,
                    'create_folder_name': folder_name}
                response = requests.post(url, data=data)
                if response.status_code == 200:
                    respo = response.json()
                    folderid = respo['folder_id']
            deleted_file = FolderFile()
            deleted_file.file_name = current_file_name
            deleted_file.folder_id = folderid
            deleted_file.user_id_id = user_id
            deleted_file.save()
            current_file.delete()
            all_files = FolderFile.objects.filter(folder_id=folderid)
            json_list = []
            excel_file_icon = '<i class="fa fa-file-excel-o" style="font-size:30px;color:#3CB371"></i>'
            pdf_file_icon = '<i class="fa fa-file-pdf-o" style="font-size:30px;color:#DC143C" aria-hidden="true"></i>'
            word_file_icon = '<i class="fa fa-file-word-o" style="font-size:30px;color:#00BFFF;" aria-hidden="true"></i>'
            text_icon = '<i class="fa fa-file-text" style="font-size:30px;color:#808080;" aria-hidden="true"></i>'
            zip_file_icon = '<i class="fa fa-file-archive-o"  style="font-size:30px;color:#FFA500" aria-hidden="true"></i>'
            mp3_icon = '<i class="fas fa-music" style="font-size:30px;color:#FF6600"></i>'
            mp4_icon = '<i class="fa fa-play" style="font-size:30px;color:#FF00CC" aria-hidden="true"></i>'
            json_list.append(folder_name)
            for items in all_files:
                url = str(items.file_name)
                a = urlparse(url)
                file_name = os.path.basename(a.path)
                name, ext = os.path.splitext(file_name)
                if ext.lower() == '.jpg' or ext.lower() == '.jpeg' or ext.lower() == '.png':
                    json_list.append({
                        'item': items.file_name.url, 'file_name': file_name, 'icon': '', 'item_id': items.id
                    })
                elif ext.lower() == '.xlsx':
                    json_list.append({
                        'item': items.file_name.url, 'file_name': file_name, 'icon': excel_file_icon,
                        'item_id': items.id
                    })
                elif ext.lower() == '.pdf':
                    json_list.append({
                        'item': items.file_name.url, 'file_name': file_name, 'icon': pdf_file_icon, 'item_id': items.id
                    })
                elif ext.lower() == '.docx':
                    json_list.append({
                        'item': items.file_name.url, 'file_name': file_name, 'icon': word_file_icon, 'item_id': items.id
                    })
                elif ext.lower() == '.txt':
                    json_list.append({
                        'item': items.file_name.url, 'file_name': file_name, 'icon': text_icon, 'item_id': items.id
                    })
                elif ext.lower() == '.zip':
                    json_list.append({
                        'item': items.file_name.url, 'file_name': file_name, 'icon': zip_file_icon, 'item_id': items.id
                    })
                elif ext.lower() == '.mp3':
                    json_list.append({
                        'item': "", 'file_name': file_name, 'icon': mp3_icon, 'item_id': items.id
                    })
                elif ext.lower() == '.mkv' or ext.lower() == '.mp4' or ext.lower() == '.flv' or ext.lower() == '.avi' or ext.lower() == '.wmv' or ext.lower() == '.m4p' or ext.lower() == '.m4v' or ext.lower() == '.mpg' or ext.lower() == '.mp2' or ext.lower() == '.mpeg' or ext.lower() == '.mpe' or ext.lower() == '.nsv' or ext.lower() == '.3gp' or ext.lower() == '.mpv':
                    json_list.append({
                        'item': "", 'file_name': file_name, 'icon': mp4_icon, 'item_id': items.id
                    })
        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')


class DeleteTrashFolderView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        folder_name = data.get('folder_id')
        if folder_name:
            folder_to_delete = DeletedFileFolder.objects.filter(folder_name=folder_name, is_deleted=False).first()

            RecoveryDeletedFileFolder.objects.create(
                folder_name=folder_to_delete.folder_name,
                user_id=folder_to_delete.user_id

            )
            DeletedFileFolder.objects.filter(folder_name=folder_name, is_deleted=False).update(is_deleted = True)
            folder_to_delete.delete()
        delete_fold = DeletedFileFolder.objects.filter(folder_name=folder_name)
        delete_fold.delete()
        json_list = []
        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')


def re_email_activation_login(request, *args, **kwargs):
    uid = kwargs.get('uidb64')
    if uid:
        decoded_user_id = urlsafe_base64_decode(uid)
        print(decoded_user_id)
        user = RegisterUser.objects.get(id=decoded_user_id)
        user.active_email = True
        user.save()
        return render(request, 'digital_locker_signin.html')

def reactivate_render(request):
    """
    this function use to render signup html fileregister/
    """
    return render(request, 'activate_input_email.html')

class ResendActivateAPIView(APIView):
    model = RegisterUser
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        email = data.get('email')
        dm = RegisterUser.objects.filter(email__iexact=email)
        if dm.exists():
            d = RegisterUser.objects.filter(email__iexact=email).values('token', 'id')
            a = list(d.values('token', 'id'))
            token = a[0]['token']
            id = a[0]['id']
            try:
                url = settings.ROOT_URL
                ctx = {
                    'content': url,
                    'uid': urlsafe_base64_encode(force_bytes(id)),
                    'token':token,
                }
                sender_email = settings.EMAIL_HOST_USER
                message = get_template('activition_email.html').render(ctx)
                msg = EmailMessage(
                    'Account Activition Email - Digilocker',
                    message,
                    sender_email,
                    [email],
                )
                msg.content_subtype = "html"
                msg.send()

            except Exception as e:
                print(e)

            response = {
                'status': "success",
                'code': status.HTTP_200_OK,
                'message': 'An Activation has send to your email address.To activate your account as a registered account and Login , you have to click on that link'
            }
        else:
            response = {
                'status': "error",
                'code': status.HTTP_200_OK,
                'message': 'This User id  or Email already activate'
            }
        return Response(response)
def folderpasswordupdate(request):
    if not request.session:
        return redirect
    user_id = request.session['user_id']
    if user_id != request.session['user_id']:
        return redirect('login_render')
    else:
        if request.method == "POST":
            folder_password = request.POST['folder_password']
            folder_id = request.POST['folder_id']
            user_id = request.session['user_id']

            folderfile = Folder.objects.get(
                id=folder_id, user_id_id=user_id)
            pass_f = folderfile.folder_password
            if len(pass_f) != 0:
                if folder_password == pass_f:
                    response = {
                    'status': 'Failed',
                    'message': 'Password not Updated'
                    }
                else:
                    folderfile.folder_password = folder_password
                    folderfile.is_locked = True
                    folderfile.pass_present = True
                    folderfile.save()
                    response = {
                        'status': 'Success',

                        'message': 'Password Updated'
                    }
                return JsonResponse(response)
            else:
                folderfile.folder_password = folder_password
                folderfile.is_locked = True
                folderfile.pass_present = True
                folderfile.save()
                response = {
                    'status': 'Success',

                    'message': 'Password Updated'
                }
                return JsonResponse(response)


def validate_password(request):
    if request.method == "POST":
        password = request.POST['folderpassword']
        folder_id = request.POST['folder_id']
        n_pass = Folder.objects.get(id=folder_id)
        f_pass = n_pass.folder_password

        if password == f_pass:
            # Password matches, unlock the folder
            folder = Folder.objects.get(id=folder_id)
            folder.is_locked = False
            folder.save()
            return JsonResponse({'valid': True})
        else:

            return JsonResponse({'valid': False})


class RestoreFolder(APIView):
    permission_classes = [permissions.AllowAny]

    def get_next_folder_name(self, base_name):
        existing_folders = Folder.objects.filter(folder_name__startswith=base_name).order_by('-folder_name')

        if existing_folders.exists():
            last_folder_name = existing_folders.first().folder_name
            try:
                last_number = int(last_folder_name[len(base_name):])
                new_number = last_number + 1
            except ValueError:
                new_number = 1
        else:
            new_number = 1

        return f"{base_name}{new_number}"

    def post(self, request, *args, **kwargs):
        data = request.data
        user_id = request.session['user_id']
        folder_name = data.get('folder_id')

        if folder_name:
            current_folder = DeletedFileFolder.objects.filter(folder_name=folder_name).exclude(file_name='').exists()

            if Folder.objects.filter(folder_name=folder_name).exists():
                new_folder_name = self.get_next_folder_name(folder_name)
                restore_folder = Folder.objects.create(folder_name=new_folder_name, user_id_id=user_id)
            else:
                restore_folder = Folder.objects.create(folder_name=folder_name, user_id_id=user_id)

            if current_folder:
                # Restore associated files
                files = DeletedFileFolder.objects.filter(folder_name=folder_name).exclude(file_name='')
                for file in files:
                    FolderFile.objects.create(file_name=file.file_name, folder=restore_folder, user_id_id=user_id)

        current_folders = DeletedFileFolder.objects.filter(folder_name=folder_name)
        current_folders.delete()
        json_list = []
        data = json.dumps(json_list)
        return HttpResponse(data, content_type='application/json')


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def restore_all_view(request):
    # Restore all folders with files
    user_id = request.session['user_id']
    deleted_all_folders = DeletedFileFolder.objects.filter(user_id_id=user_id).values('folder_name')
    deleted_folders = deleted_all_folders.distinct()
    for deleted_folder in deleted_folders:
        folder_name = deleted_folder['folder_name']
        folder = Folder.objects.create(folder_name=folder_name, user_id_id=user_id)
        files = DeletedFileFolder.objects.filter(folder_name=folder_name).values('file_name')
        for deleted_file in files:
            file_name = deleted_file['file_name']
            if file_name:
                FolderFile.objects.create(file_name=file_name, folder=folder, user_id_id=user_id)
            else:
                break
    deleted_all = DeletedFileFolder.objects.filter(user_id_id=user_id)
    deleted_all.delete()
    return Response({"message": "Files restored successfully."})


def forgotfolderpassword(request):
    if request.method == "POST":
        password = request.POST['forgotfolderpassword']
        print("password", password)
        response = {
            'status': 'Success',

            'message': 'Password Updated'
        }
        return render(response)


def folderpasswordreupdate(request):
    if not request.session:
        return redirect
    user_id = request.session['user_id']
    if user_id != request.session['user_id']:
        return redirect('login_render')
    else:
        if request.method == "POST":
            password = request.POST['folderpassword']
            folder_id = request.POST['folder_id']
            re_pass = Folder.objects.get(id=folder_id)
            old_pass = re_pass.folder_password
            if old_pass == password:
                re_pass.is_locked = True
                re_pass.save()
                response = {
                    'status': 'Success',
                    'message': 'Password Updated'
                }
            else:
                response = {
                    'status': 'Failed',
                    'message': 'Password not Updated'
                }
            return JsonResponse(response)


def reset_folderpassword(request):

    return render(request, 'reset_folderpassword.html')

import uuid
def reset_folder_password(request):
    folder_id = request.GET.get('folder_id')
    email = request.GET.get('email')
    reset_link_uuid = str(uuid.uuid4())
    reset_link = request.build_absolute_uri(reverse('reset_folderpassword_link_template', args=[folder_id, reset_link_uuid]))

    send_mail(
        'Reset Folder Password',
        f'Here is your password reset link: {reset_link}',
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )
    return JsonResponse({'message': 'Reset Folder Password link send on your email address Successfully'})


def reset_folder_password_template(request, folder_id, uuid):


    context = {
        'folder_id': folder_id,
        'uuid': uuid,
    }

    return render(request, 'reset_folderpassword.html', context)

def reset_folder_password_logic(request, folder_id, uuid):
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            return render(request, 'reset_password_error.html')  # Render error page if passwords don't match

        try:
            folder = Folder.objects.get(id=folder_id)
            folder.folder_password = new_password
            folder.save()

            return render(request, 'reset_password_success.html')  # Render success page after password reset
        except Folder.DoesNotExist:
            return render(request, 'reset_password_error.html')

    return render(request, 'reset_password_error.html')


class CopyFilesView(APIView):
    """
    this class handels copy files to desired folders
    """
    permission_classes = [permissions.AllowAny]

    def copy_file_to_folder(self, file_item, destination_folder):
        # Create a new file entry in the destination folder
        new_file_item = FolderFile.objects.create(
            user_id=file_item.user_id,
            folder=destination_folder,
            file_name=file_item.file_name,
            only_file_name=file_item.only_file_name,
        )
    def post(self, request, *args, **kwargs):
        data = request.data
        loggedin_user_id = request.session['user_id']
        loggedin_user = RegisterUser.objects.get(id=loggedin_user_id)
        loggedin_user_name = loggedin_user.user_id
        data = request.data
        item_ids = data.get('share_files_ids')
        share_files_ids = item_ids.split(",")
        recived_people = data.get('share_people_ids')
        recived_folder_id = recived_people.split(",")
        try:
            for item_id in share_files_ids:
                file_item = FolderFile.objects.get(id=int(item_id))

                for folder_id in recived_folder_id:
                    destination_folder = Folder.objects.get(id=int(folder_id))
            self.copy_file_to_folder(file_item, destination_folder)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Files copied successfully.'
            }
            return Response(response)

        except Exception as e:
            print(e)
            response = {
                'status': 'error',
                'code': status.HTTP_200_OK,
                'message': 'Something went wrong while copying files.'
            }
            return Response(response)



class MoveFilesView(APIView):
    """
    this class handels copy files to desired folders
    """
    permission_classes = [permissions.AllowAny]

    def move_file_to_folder(self, file_item, destination_folder):
        # Create a new file entry in the destination folder
        new_file_item = FolderFile.objects.create(
            user_id=file_item.user_id,
            folder=destination_folder,
            file_name=file_item.file_name,
            only_file_name=file_item.only_file_name,
        )

        file_item.delete()
    def post(self, request, *args, **kwargs):
        data = request.data
        loggedin_user_id = request.session['user_id']
        loggedin_user = RegisterUser.objects.get(id=loggedin_user_id)
        loggedin_user_name = loggedin_user.user_id
        data = request.data
        item_ids = data.get('share_files_ids')
        share_files_ids = item_ids.split(",")
        recived_people = data.get('share_people_ids')
        recived_folder_id = recived_people.split(",")
        try:
            for item_id in share_files_ids:
                file_item = FolderFile.objects.get(id=int(item_id))

                for folder_id in recived_folder_id:
                    destination_folder = Folder.objects.get(id=int(folder_id))
            self.move_file_to_folder(file_item, destination_folder)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Files copied successfully.'
            }
            return Response(response)

        except Exception as e:
            print(e)
            response = {
                'status': 'error',
                'code': status.HTTP_200_OK,
                'message': 'Something went wrong while copying files.'
            }
            return Response(response)


def folder_reorder(request):
    if request.method == 'POST':
        folder_id = request.POST.get('folder_id')
        direction = request.POST.get('direction')

        folder = Folder.objects.get(id=folder_id)
        current_position = folder.position

        if current_position is None:
            return HttpResponse(status=400)  # Return a bad request response if current_position is None

        if direction == 'up':
            swap_folder = Folder.objects.filter(position=current_position - 1).first()
        elif direction == 'down':
            swap_folder = Folder.objects.filter(position=current_position + 1).first()

        if swap_folder:
            # Swap positions
            folder.position, swap_folder.position = swap_folder.position, folder.position
            folder.save()
            swap_folder.save()

        return HttpResponse(status=204)  # Return an empty response with status code 204
    else:
        return HttpResponse(status=400)  # Return a bad request response if method is not POST

from django.http import JsonResponse

def move_file(request, folder_id, file_id):
    if request.method == 'POST' and request.is_ajax():
        new_index = int(request.GET.get('new_index', 0))

        try:
            folder_file = FolderFile.objects.get(id=file_id, folder_id=folder_id)
            old_index = folder_file.file_order

            # Update file orders within the same folder
            if new_index < old_index:
                FolderFile.objects.filter(folder_id=folder_id, file_order__gte=new_index, file_order__lt=old_index).update(file_order=models.F('file_order') + 1)
            elif new_index > old_index:
                FolderFile.objects.filter(folder_id=folder_id, file_order__gt=old_index, file_order__lte=new_index).update(file_order=models.F('file_order') - 1)

            # Set the new order for the moved file
            folder_file.file_order = new_index
            folder_file.save()

            return JsonResponse({'message': 'File moved successfully'})
        except FolderFile.DoesNotExist:
            return JsonResponse({'error': 'File not found'})
    else:
        return JsonResponse({'error': 'Invalid request'})
