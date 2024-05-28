from django.shortcuts import render
import pytz
from django.utils import timezone
from django.shortcuts import render, redirect
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, renderer_classes
from django.http import JsonResponse
from rest_framework import status
from rest_framework import generics, permissions, mixins
from account.models import RegisterUser, Folder, Profile, FolderFile, DeletedFileFolder, ShareFile, NonRegisterFolderFile \
    ,UploadFiles2
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

from .api.serializers import FileDownloadSerializer, FolderFileSerializer, TrashSerializer, ChangePasswordSerializer, ProfileSerializer, FolderSerializer, UserDisplaySerializer, MemberSerializer, FolderUploadSerializer
from .api.validatemymail import *
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
from .api.utils import get_icon, get_real_filesize
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.urls import reverse, reverse_lazy
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.hashers import make_password

# Create your views here.
def login_render(request, *args, **kwargs):
    """
    this function use to render singin html file
    """

    return render(request, 'digital_locker_signin.html')



def register_render(request):
    """
    this function use to render signup html fileregister/
    """
    return render(request, 'digital_locker_signup.html')


def home_page_render(request):
    """
    this function is used to render main page of digilocker with folders and items of current logged in user
    """

    if not request.session:
        return redirect
    user_id = request.session['user_id']
    if user_id != request.session['user_id']:
        return redirect('login_render')
    else:
        request.session['trash_offset'] = 0
        request.session['trash_end'] = 7
        request.session['share_offset'] = 0
        request.session['share_end'] = 7
        request.session['folder_offset'] = 0
        request.session['folder_end'] = 5
        render_user = RegisterUser.objects.exclude(id=user_id)[0:6]

        current_user = RegisterUser.objects.get(id=user_id)
        current_user_name = current_user.user_id
        current_user_name_display = current_user.display_name
        default_size = int(current_user.default_size)
        uploaded_size = int(current_user.uploaded_size)
        remaining_size = default_size - uploaded_size
        all_user = RegisterUser.objects.exclude(id=user_id)
        all_folders = Folder.objects.filter(user_id_id=user_id)
        user = RegisterUser.objects.get(id=user_id)
        profile_pic = user.profile_pic
        ### ALL FOLDER
        result = []
        unique_folder = Folder.objects.filter(user_id_id=user_id)
        for item in unique_folder:
            product = []
            folder_name = Folder.objects.get(id=item.id)
            all_items = FolderFile.objects.filter(folder_id=item.id).iterator()
            all_item_count = FolderFile.objects.filter(
                folder_id=item.id).count()
            for_size = FolderFile.objects.filter(folder_id=item.id)
            full_size = 0
            for files in for_size:
                if files.file_name:
                    full_path = os.path.join(
                        settings.MEDIA_ROOT, str(files.file_name))
                    if os.path.isfile(full_path):
                        size = os.path.getsize(str(full_path))
                        full_size += size
           
            real_size = get_real_filesize(full_size)

            folder_lock = Folder.objects.get(id=item.id)
            n_pass = folder_lock.is_locked
            f_pass = folder_lock.pass_present
            for items in all_items:
                url = str(items.file_name)
                # print(url, flush=True)
                a = urlparse(url)
                file_name = os.path.basename(a.path)
                name, ext = os.path.splitext(file_name)
                data = {}
                if items.file_name:
                    # print(items.file_name.url, flush=True)
                    data['image'] = items.file_name.url
                    data['file_name'] = file_name
                    data['file_id'] = items.id
                    data['icon'] = get_icon(ext.lower())
                    product.append(data)

            if product:
                new = {
                    'folder_id': item.id,
                    'user_id': user_id,
                    'folder_name': folder_name.folder_name,
                    'products': product,
                    'count': all_item_count,
                    'real_size': real_size,
                    'is_locked':n_pass,
                    'pass_present':f_pass
                }
                result.append(new)
            else:
                new = {
                    'folder_id': item.id,
                    'user_id': user_id,
                    'folder_name': folder_name.folder_name,
                    'count': '0',
                    'is_locked': n_pass,
                    'pass_present': f_pass

                }
                result.append(new)
        all_folder = Folder.objects.filter(user_id_id=user_id)[0:5]
        ### DELETED FOLDER
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
        all_deleted = DeletedFileFolder.objects.filter(user_id_id=user_id)
        paginator = Paginator(all_deleted, 7)
        page = request.GET.get('page', 1)
        try:
            deleted = paginator.page(page)
        except PageNotAnInteger:
            deleted = paginator.page(1)
        except EmptyPage:
            deleted = paginator.page(paginator.num_pages)
        deletd_page_list = deleted.paginator.page_range

        ### Restore folder and file

        trash_data_restore = DeletedFileFolder.objects.values('folder_name').filter(user_id_id=user_id,is_deleted=False).annotate(count=Count('folder_name'))




        ## SHARED FOLDER

        shared_data = ShareFile.objects.values('sender_name').filter(reciver_id=user_id, reciver_checked=True).annotate(count=Count('sender_name'))
        shared_item_list = []
        type_graph_result_shared = []
        for row in shared_data:
            sender_name = row['sender_name']
            shared_item = ShareFile.objects.filter(reciver_id=user_id, reciver_checked=True, sender_name=sender_name).order_by('-id')[0:7]
            datas = {}
            datas['folder_name'] = sender_name
            item_list = []
            current_file_type = []
            current_file_graph = []
            for item in shared_item:
                data = {}
                if item.file_id != "":
                    url = str(item.file_id)
                    a = urlparse(url)
                    file_name = os.path.basename(a.path)
                    name, ext = os.path.splitext(file_name)
                    data[item.id] = ext
                    current_file_type.append(data)
                    icon = get_icon(ext.lower())
                    item_list.append({'icon': icon,'reciver':item.reciver,'sender_name': item.sender_name, 'file_url': item.file_id.url, 'file_name': file_name, 'file_id': item.id})
            datas['file'] = item_list
            shared_item_list.append(datas)

            merged_dictionary = {}
            for dictionary in current_file_type:
                for key, value in dictionary.items():
                    merged_dictionary[key] = value

            count_dic = {}
            for k, v in merged_dictionary.items():
                count_dic[v] = count_dic.get(v, 0) + 1

            if len(count_dic)!= 0:
                for key, value in count_dic.items():
                    current_file_graph.append({
                        'name': str(key), 'y': value, 'selected': 'true'
                    })
            else:
                current_file_graph.append({
                    'name': 'capacity', 'y': 100
                })
            whole_type = {
                'folder_id': item.sender_name,
                'graph': current_file_graph
            }
            type_graph_result_shared.append(whole_type)

       

        # for items in shared_item:
        #     if items.file_id == "":
        #         items.delete()
        # paginator = Paginator(shared_item, 7)
        # page = request.GET.get('page', 1)

        # try:
        #     shared = paginator.page(page)
        # except PageNotAnInteger:
        #     shared = paginator.page(1)
        # except EmptyPage:
        #     shared = paginator.page(paginator.num_pages)
        # shared_pages = shared.paginator.page_range
        shared_pages = ''
        # rendering highchart into the fronend #
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
                # files = [item.file_name for item in all_current_files if os.path.splitext(item.file_name.name)[1] == key]
                # print("fffffffffffff", files)
                graph_data_outer.append({
                    'name': str(key), 'y': value, 'selected': 'true', #'files': files
                })
        else:
            graph_data_outer.append({
                'name': 'capacity', 'y': 100, #'files': []
            })

        current_user_folder = Folder.objects.filter(user_id_id=user_id)
        type_graph_result_inner = []
        for item in current_user_folder:
            current_files = FolderFile.objects.filter(folder_id=item.id)
            current_file_type = []
            current_file_graph = []
            for items in current_files:
                data = {}
                filepath = os.path.join(
                    settings.MEDIA_ROOT, str(items.file_name))
                name, extension = os.path.splitext(filepath)
                data[items.id] = extension
                current_file_type.append(data)

            merged_dictionary = {}
            for dictionary in current_file_type:
                for key, value in dictionary.items():
                    merged_dictionary[key] = value

            count_dic = {}
            for k, v in merged_dictionary.items():
                count_dic[v] = count_dic.get(v, 0) + 1

            if len(count_dic)!= 0:
                for key, value in count_dic.items():
                    current_file_graph.append({
                        'name': str(key), 'y': value, 'selected': 'true'
                    })
            else:
                current_file_graph.append({
                    'name': 'capacity', 'y': 100
                })
            whole_type = {
                'folder_id': item.id,
                'graph': current_file_graph
            }
            type_graph_result_inner.append(whole_type)
        # print("type_graph_result_inner", type_graph_result_inner)
        # print("graph_data_outer", graph_data_outer)
        # total folder , file , MB count
        total_folder = Folder.objects.filter(user_id_id=user_id).count()

        total_files = FolderFile.objects.filter(user_id_id=user_id).count()
        whole_size = FolderFile.objects.filter(user_id_id=user_id)
        full_folderfile_size = 0
        for fileitem in whole_size:
            file_full_path = os.path.join(
                settings.MEDIA_ROOT, str(fileitem.file_name))
            if os.path.isfile(file_full_path):
                file_size = os.path.getsize(str(file_full_path))
                full_folderfile_size += file_size
        if full_folderfile_size > 1073741824:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1073741824)) + " GB"
        elif full_folderfile_size > 1048576:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1048576)) + " MB"
        else:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1024)) + " KB"

        return render(request, 'index.html', {'real_filefolder_size': real_filefolder_size, 'total_folder': total_folder, 'total_files': total_files, 'graph_data_outer': graph_data_outer, 'type_graph_result_inner': type_graph_result_inner,'type_graph_result_shared': type_graph_result_shared, 'current_user_name': current_user_name, 'result': result, 'remaining_size': remaining_size, 'shared_item_list': shared_item_list, 'shared_pages': shared_pages, 'deletd_page_list': deletd_page_list, 'profile_pic': profile_pic, 'share_people': all_user, 'all_user': render_user, 'list_of_folder': all_folder, 'delete_folder_file': delete_folder_file, 'current_user_name_display': current_user_name_display, 'copy_folder': all_folders})


def shared_page_render(request):
    """
    this function is used to render main page of digilocker with folders and items of current logged in user
    """

    if not request.session:
        return redirect
    user_id = request.session['user_id']
    if user_id != request.session['user_id']:
        return redirect('login_render')
    else:
        request.session['trash_offset'] = 0
        request.session['trash_end'] = 7
        request.session['share_offset'] = 0
        request.session['share_end'] = 7
        request.session['folder_offset'] = 0
        request.session['folder_end'] = 5
        render_user = RegisterUser.objects.exclude(id=user_id)[0:6]

        current_user = RegisterUser.objects.get(id=user_id)
        current_user_name = current_user.user_id
        current_user_name_display = current_user.display_name
        default_size = int(current_user.default_size)
        uploaded_size = int(current_user.uploaded_size)
        remaining_size = default_size - uploaded_size
        all_user = RegisterUser.objects.exclude(id=user_id)
        user = RegisterUser.objects.get(id=user_id)
        profile_pic = user.profile_pic

        ## SHARED FOLDER

        shared_data = ShareFile.objects.values('sender_name').filter(reciver_id=user_id, reciver_checked=True).annotate(count=Count('sender_name'))
        shared_item_list = []
        type_graph_result_shared = []
        for row in shared_data:
            sender_name = row['sender_name']
            shared_item = ShareFile.objects.filter(reciver_id=user_id, reciver_checked=True, sender_name=sender_name).order_by('-id')[0:7]
            datas = {}
            datas['folder_name'] = sender_name
            item_list = []
            current_file_type = []
            current_file_graph = []
            full_folderfile_size = 0
            file_counter = 0
            for item in shared_item:
                data = {}
                if item.file_id != "":
                    url = str(item.file_id)
                    a = urlparse(url)
                    file_name = os.path.basename(a.path)
                    file_full_path = os.path.join(
                        settings.MEDIA_ROOT, str(item.file_id))
                    if os.path.isfile(file_full_path):
                        file_size = os.path.getsize(str(file_full_path))
                        full_folderfile_size += file_size
                    name, ext = os.path.splitext(file_name)
                    data[item.id] = ext
                    current_file_type.append(data)
                    icon = get_icon(ext.lower())
                    item_list.append({'icon': icon,'reciver':item.reciver,'sender_name': item.sender_name, 'file_url': item.file_id.url, 'file_name': file_name, 'file_id': item.id})
                file_counter = file_counter + 1
            datas['file'] = item_list
            datas['file_count'] = file_counter
            shared_item_list.append(datas)
            print(shared_item_list, flush=True)

            if full_folderfile_size > 1073741824:
                real_filefolder_size = str(
                    round(int(full_folderfile_size)/1073741824)) + " GB"
            elif full_folderfile_size > 1048576:
                real_filefolder_size = str(
                    round(int(full_folderfile_size)/1048576)) + " MB"
            else:
                real_filefolder_size = str(
                    round(int(full_folderfile_size)/1024)) + " KB"
            datas['file_size'] = real_filefolder_size

            

            merged_dictionary = {}
            for dictionary in current_file_type:
                for key, value in dictionary.items():
                    merged_dictionary[key] = value

            count_dic = {}
            for k, v in merged_dictionary.items():
                count_dic[v] = count_dic.get(v, 0) + 1

            if len(count_dic)!= 0:
                for key, value in count_dic.items():
                    current_file_graph.append({
                        'name': str(key), 'y': value, 'selected': 'true'
                    })
            else:
                current_file_graph.append({
                    'name': 'capacity', 'y': 100
                })
            whole_type = {
                'folder_id': item.sender_name,
                'graph': current_file_graph
            }
            type_graph_result_shared.append(whole_type)

       

        # for items in shared_item:
        #     if items.file_id == "":
        #         items.delete()
        # paginator = Paginator(shared_item, 7)
        # page = request.GET.get('page', 1)

        # try:
        #     shared = paginator.page(page)
        # except PageNotAnInteger:
        #     shared = paginator.page(1)
        # except EmptyPage:
        #     shared = paginator.page(paginator.num_pages)
        # shared_pages = shared.paginator.page_range
        shared_pages = ''
        # rendering highchart into the fronend #
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

        
        # total folder , file , MB count
        total_folder = Folder.objects.filter(user_id_id=user_id).count()

        total_files = FolderFile.objects.filter(user_id_id=user_id).count()
        whole_size = FolderFile.objects.filter(user_id_id=user_id)
        full_folderfile_size = 0
        for fileitem in whole_size:
            file_full_path = os.path.join(
                settings.MEDIA_ROOT, str(fileitem.file_name))
            if os.path.isfile(file_full_path):
                file_size = os.path.getsize(str(file_full_path))
                full_folderfile_size += file_size
        if full_folderfile_size > 1073741824:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1073741824)) + " GB"
        elif full_folderfile_size > 1048576:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1048576)) + " MB"
        else:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1024)) + " KB"
        # print(shared_item_list)
        print(type_graph_result_shared)
        return render(request, 'shared_item.html', {'real_filefolder_size': real_filefolder_size, 'total_folder': total_folder, 'total_files': total_files, 'graph_data_outer': graph_data_outer,'type_graph_result_shared': type_graph_result_shared, 'current_user_name': current_user_name, 'remaining_size': remaining_size, 'shared_item_list': shared_item_list, 'shared_pages': shared_pages, 'profile_pic': profile_pic, 'share_people': all_user, 'all_user': render_user, 'current_user_name_display': current_user_name_display})




def member_render(request):
    """
    this function is used to render main page of digilocker with folders and items of current logged in user
    """

    if not request.session:
        return redirect
    user_id = request.session['user_id']
    if user_id != request.session['user_id']:
        return redirect('login_render')
    else:
        request.session['trash_offset'] = 0
        request.session['trash_end'] = 7
        request.session['share_offset'] = 0
        request.session['share_end'] = 7
        request.session['folder_offset'] = 0
        request.session['folder_end'] = 5
        render_user = RegisterUser.objects.exclude(id=user_id)[0:6]

        current_user = RegisterUser.objects.get(id=user_id)
        current_user_name = current_user.user_id
        current_user_name_display = current_user.display_name
        default_size = int(current_user.default_size)
        uploaded_size = int(current_user.uploaded_size)
        remaining_size = default_size - uploaded_size
        all_user = RegisterUser.objects.exclude(id=user_id)

        user = RegisterUser.objects.get(id=user_id)
        profile_pic = user.profile_pic

        ## SHARED FOLDER

        shared_data = ShareFile.objects.values('sender_name').filter(reciver_id=user_id, reciver_checked=True).annotate(count=Count('sender_name'))
        shared_item_list = []
        type_graph_result_shared = []
        for row in shared_data:
            sender_name = row['sender_name']
            shared_item = ShareFile.objects.filter(reciver_id=user_id, reciver_checked=True, sender_name=sender_name).order_by('-id')[0:7]
            datas = {}
            datas['folder_name'] = sender_name
            item_list = []
            current_file_type = []
            current_file_graph = []
            for item in shared_item:
                data = {}
                if item.file_id != "":
                    url = str(item.file_id)
                    a = urlparse(url)
                    file_name = os.path.basename(a.path)
                    name, ext = os.path.splitext(file_name)
                    data[item.id] = ext
                    current_file_type.append(data)
                    icon = get_icon(ext.lower())
                    item_list.append({'icon': icon,'reciver':item.reciver,'sender_name': item.sender_name, 'file_url': item.file_id.url, 'file_name': file_name, 'file_id': item.id})
            datas['file'] = item_list
            shared_item_list.append(datas)

            merged_dictionary = {}
            for dictionary in current_file_type:
                for key, value in dictionary.items():
                    merged_dictionary[key] = value

            count_dic = {}
            for k, v in merged_dictionary.items():
                count_dic[v] = count_dic.get(v, 0) + 1

            if len(count_dic)!= 0:
                for key, value in count_dic.items():
                    current_file_graph.append({
                        'name': str(key), 'y': value, 'selected': 'true'
                    })
            else:
                current_file_graph.append({
                    'name': 'capacity', 'y': 100
                })
            whole_type = {
                'folder_id': item.sender_name,
                'graph': current_file_graph
            }
            type_graph_result_shared.append(whole_type)

       

        # for items in shared_item:
        #     if items.file_id == "":
        #         items.delete()
        # paginator = Paginator(shared_item, 7)
        # page = request.GET.get('page', 1)

        # try:
        #     shared = paginator.page(page)
        # except PageNotAnInteger:
        #     shared = paginator.page(1)
        # except EmptyPage:
        #     shared = paginator.page(paginator.num_pages)
        # shared_pages = shared.paginator.page_range
        shared_pages = ''
        # rendering highchart into the fronend #
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

        
        # total folder , file , MB count
        total_folder = Folder.objects.filter(user_id_id=user_id).count()

        total_files = FolderFile.objects.filter(user_id_id=user_id).count()
        whole_size = FolderFile.objects.filter(user_id_id=user_id)
        full_folderfile_size = 0
        for fileitem in whole_size:
            file_full_path = os.path.join(
                settings.MEDIA_ROOT, str(fileitem.file_name))
            if os.path.isfile(file_full_path):
                file_size = os.path.getsize(str(file_full_path))
                full_folderfile_size += file_size
        if full_folderfile_size > 1073741824:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1073741824)) + " GB"
        elif full_folderfile_size > 1048576:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1048576)) + " MB"
        else:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1024)) + " KB"

        return render(request, 'profile_list.html', {'real_filefolder_size': real_filefolder_size, 'total_folder': total_folder, 'total_files': total_files, 'graph_data_outer': graph_data_outer,'type_graph_result_shared': type_graph_result_shared, 'current_user_name': current_user_name, 'remaining_size': remaining_size, 'shared_item_list': shared_item_list, 'shared_pages': shared_pages, 'profile_pic': profile_pic, 'share_people': all_user, 'all_user': render_user, 'current_user_name_display': current_user_name_display})




def trash_render(request):
    """
    this function is used to render main page of digilocker with folders and items of current logged in user
    """

    if not request.session:
        return redirect
    user_id = request.session['user_id']
    if user_id != request.session['user_id']:
        return redirect('login_render')
    else:
        request.session['trash_offset'] = 0
        request.session['trash_end'] = 7
        request.session['share_offset'] = 0
        request.session['share_end'] = 7
        request.session['folder_offset'] = 0
        request.session['folder_end'] = 5
        render_user = RegisterUser.objects.exclude(id=user_id)[0:6]

        current_user = RegisterUser.objects.get(id=user_id)
        current_user_name = current_user.user_id
        current_user_name_display = current_user.display_name
        default_size = int(current_user.default_size)
        uploaded_size = int(current_user.uploaded_size)
        remaining_size = default_size - uploaded_size
        all_user = RegisterUser.objects.exclude(id=user_id)

        user = RegisterUser.objects.get(id=user_id)
        profile_pic = user.profile_pic
        ### ALL FOLDER
        result = []
        unique_folder = Folder.objects.filter(user_id_id=user_id)
        for item in unique_folder:
            product = []
            folder_name = Folder.objects.get(id=item.id)
            all_items = FolderFile.objects.filter(folder_id=item.id).iterator()
            all_item_count = FolderFile.objects.filter(
                folder_id=item.id).count()
            for_size = FolderFile.objects.filter(folder_id=item.id)
            full_size = 0
            for files in for_size:
                if files.file_name:
                    full_path = os.path.join(
                        settings.MEDIA_ROOT, str(files.file_name))
                    if os.path.isfile(full_path):
                        size = os.path.getsize(str(full_path))
                        full_size += size
           
            real_size = get_real_filesize(full_size)

            for items in all_items:
                url = str(items.file_name)
                # print(url, flush=True)
                a = urlparse(url)
                file_name = os.path.basename(a.path)
                name, ext = os.path.splitext(file_name)
                data = {}
                if items.file_name:
                    # print(items.file_name.url, flush=True)
                    data['image'] = items.file_name.url
                    data['file_name'] = file_name
                    data['file_id'] = items.id
                    data['icon'] = get_icon(ext.lower())
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

        all_folder = Folder.objects.filter(user_id_id=user_id)[0:5]
        ### DELETED FOLDER
        # delete_folder_file = []
        # current_user_item = DeletedFileFolder.objects.filter(
        #     user_id_id=user_id).order_by('-id')[0:7]
        # for item in current_user_item:
        #     url = str(item.file_name)
        #     a = urlparse(url)
        #     file_name = os.path.basename(a.path)
        #     if item.file_name:
        #         delete_folder_file.append({
        #             'folder': item.folder_name, 'file_url': item.file_name.url, 'file_name': file_name, 'file_id': item.id
        #         })
        #     else:
        #         delete_folder_file.append({
        #             'folder': item.folder_name, 'file_url': item.file_name, 'file_name': file_name, 'file_id': item.id
        #         })
        # all_deleted = DeletedFileFolder.objects.filter(user_id_id=user_id)
        # paginator = Paginator(all_deleted, 7)
        # page = request.GET.get('page', 1)
        # try:
        #     deleted = paginator.page(page)
        # except PageNotAnInteger:
        #     deleted = paginator.page(1)
        # except EmptyPage:
        #     deleted = paginator.page(paginator.num_pages)
        # deletd_page_list = deleted.paginator.page_range



        trash_data = DeletedFileFolder.objects.values('folder_name').filter(user_id_id=user_id,is_deleted=False).annotate(count=Count('folder_name'))
        shared_item_list = []
        type_graph_result_shared = []
        
        for row in trash_data:

            shared_item = DeletedFileFolder.objects.filter(user_id_id=user_id, folder_name=row['folder_name'], is_deleted=False)
            datas = {}
            datas['folder_name'] = row['folder_name']
            item_list = []
            current_file_type = []
            current_file_graph = []
            file_counter = 0
            full_folderfile_size = 0
            for item in shared_item:
                data = {}
                if item.file_name != "":
                    url = str(item.file_name)
                    a = urlparse(url)
                    file_name = os.path.basename(a.path)

                    file_full_path = os.path.join(
                        settings.MEDIA_ROOT, str(item.file_name))
                    if os.path.isfile(file_full_path):
                        file_size = os.path.getsize(str(file_full_path))
                        full_folderfile_size += file_size

                    name, ext = os.path.splitext(file_name)
                    data[item.id] = ext
                    current_file_type.append(data)
                    icon = get_icon(ext.lower())
                    item_list.append({'icon': icon, 'file_url': item.file_name.url, 'file_name': file_name, 'file_id': item.id})
                file_counter = file_counter + 1

            if not item_list:
                file_counter = 0

            datas['file'] = item_list
            datas['file_count'] = file_counter
            shared_item_list.append(datas)

            if full_folderfile_size > 1073741824:
                real_filefolder_size = str(
                    round(int(full_folderfile_size)/1073741824)) + " GB"
            elif full_folderfile_size > 1048576:
                real_filefolder_size = str(
                    round(int(full_folderfile_size)/1048576)) + " MB"
            else:
                real_filefolder_size = str(
                    round(int(full_folderfile_size)/1024)) + " KB"
            datas['file_size'] = real_filefolder_size

            merged_dictionary = {}
            for dictionary in current_file_type:
                for key, value in dictionary.items():
                    merged_dictionary[key] = value

            count_dic = {}
            for k, v in merged_dictionary.items():
                count_dic[v] = count_dic.get(v, 0) + 1

            if len(count_dic)!= 0:
                for key, value in count_dic.items():
                    current_file_graph.append({
                        'name': str(key), 'y': value, 'selected': 'true'
                    })
            else:
                current_file_graph.append({
                    'name': 'capacity', 'y': 100
                })
            whole_type = {
                'folder_id': item.folder_name,
                'graph': current_file_graph
            }
            type_graph_result_shared.append(whole_type)

       

        # for items in shared_item:
        #     if items.file_id == "":
        #         items.delete()
        # paginator = Paginator(shared_item, 7)
        # page = request.GET.get('page', 1)

        # try:
        #     shared = paginator.page(page)
        # except PageNotAnInteger:
        #     shared = paginator.page(1)
        # except EmptyPage:
        #     shared = paginator.page(paginator.num_pages)
        # shared_pages = shared.paginator.page_range
        shared_pages = ''
        # rendering highchart into the fronend #
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

        current_user_folder = Folder.objects.filter(user_id_id=user_id)
        type_graph_result_inner = []
        for item in current_user_folder:
            current_files = FolderFile.objects.filter(folder_id=item.id)
            current_file_type = []
            current_file_graph = []
            for items in current_files:
                data = {}
                filepath = os.path.join(
                    settings.MEDIA_ROOT, str(items.file_name))
                name, extension = os.path.splitext(filepath)
                data[items.id] = extension
                current_file_type.append(data)

            merged_dictionary = {}
            for dictionary in current_file_type:
                for key, value in dictionary.items():
                    merged_dictionary[key] = value

            count_dic = {}
            for k, v in merged_dictionary.items():
                count_dic[v] = count_dic.get(v, 0) + 1

            if len(count_dic)!= 0:
                for key, value in count_dic.items():
                    current_file_graph.append({
                        'name': str(key), 'y': value, 'selected': 'true'
                    })
            else:
                current_file_graph.append({
                    'name': 'capacity', 'y': 100
                })
            whole_type = {
                'folder_id': item.id,
                'graph': current_file_graph
            }
            type_graph_result_inner.append(whole_type)

        # total folder , file , MB count
        total_folder = Folder.objects.filter(user_id_id=user_id).count()

        total_files = FolderFile.objects.filter(user_id_id=user_id).count()
        whole_size = FolderFile.objects.filter(user_id_id=user_id)
        full_folderfile_size = 0
        for fileitem in whole_size:
            file_full_path = os.path.join(
                settings.MEDIA_ROOT, str(fileitem.file_name))
            if os.path.isfile(file_full_path):
                file_size = os.path.getsize(str(file_full_path))
                full_folderfile_size += file_size
        if full_folderfile_size > 1073741824:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1073741824)) + " GB"
        elif full_folderfile_size > 1048576:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1048576)) + " MB"
        else:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1024)) + " KB"

        # print(type_graph_result_shared)
        trash_data_show = DeletedFileFolder.objects.exists()
        print("trash_data_show", trash_data_show)
        return render(request, 'trash.html', {'real_filefolder_size': real_filefolder_size, 'total_folder': total_folder, 'total_files': total_files, 'graph_data_outer': graph_data_outer, 'type_graph_result_inner': type_graph_result_inner,'type_graph_result_shared': type_graph_result_shared, 'current_user_name': current_user_name, 'result': result, 'remaining_size': remaining_size, 'shared_item_list': shared_item_list, 'shared_pages': shared_pages, 'profile_pic': profile_pic, 'share_people': all_user, 'all_user': render_user, 'list_of_folder': all_folder, 'current_user_name_display': current_user_name_display, 'trash_data_show': trash_data_show})



def beta_feature_render(request):
    """
    this function is used to render main page of digilocker with folders and items of current logged in user
    """

    if not request.session:
        return redirect
    user_id = request.session['user_id']
    if user_id != request.session['user_id']:
        return redirect('login_render')
    else:
        request.session['trash_offset'] = 0
        request.session['trash_end'] = 7
        request.session['share_offset'] = 0
        request.session['share_end'] = 7
        request.session['folder_offset'] = 0
        request.session['folder_end'] = 5
        render_user = RegisterUser.objects.exclude(id=user_id)[0:6]

        current_user = RegisterUser.objects.get(id=user_id)
        current_user_name = current_user.user_id
        current_user_name_display = current_user.display_name
        default_size = int(current_user.default_size)
        uploaded_size = int(current_user.uploaded_size)
        remaining_size = default_size - uploaded_size
        all_user = RegisterUser.objects.exclude(id=user_id)

        user = RegisterUser.objects.get(id=user_id)
        profile_pic = user.profile_pic
        ### ALL FOLDER
        result = []
        unique_folder = Folder.objects.filter(user_id_id=user_id)
        for item in unique_folder:
            product = []
            folder_name = Folder.objects.get(id=item.id)
            all_items = FolderFile.objects.filter(folder_id=item.id).iterator()
            all_item_count = FolderFile.objects.filter(
                folder_id=item.id).count()
            for_size = FolderFile.objects.filter(folder_id=item.id)
            full_size = 0
            for files in for_size:
                if files.file_name:
                    full_path = os.path.join(
                        settings.MEDIA_ROOT, str(files.file_name))
                    if os.path.isfile(full_path):
                        size = os.path.getsize(str(full_path))
                        full_size += size
           
            real_size = get_real_filesize(full_size)

            for items in all_items:
                url = str(items.file_name)
                print(url, flush=True)
                a = urlparse(url)
                file_name = os.path.basename(a.path)
                name, ext = os.path.splitext(file_name)
                data = {}
                if items.file_name:
                    print(items.file_name.url, flush=True)
                    data['image'] = items.file_name.url
                    data['file_name'] = file_name
                    data['file_id'] = items.id
                    data['icon'] = get_icon(ext.lower())
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

        all_folder = Folder.objects.filter(user_id_id=user_id)[0:5]
        ### DELETED FOLDER
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
        all_deleted = DeletedFileFolder.objects.filter(user_id_id=user_id)
        paginator = Paginator(all_deleted, 7)
        page = request.GET.get('page', 1)
        try:
            deleted = paginator.page(page)
        except PageNotAnInteger:
            deleted = paginator.page(1)
        except EmptyPage:
            deleted = paginator.page(paginator.num_pages)
        deletd_page_list = deleted.paginator.page_range

        ## SHARED FOLDER

        shared_data = ShareFile.objects.values('sender_name').filter(reciver_id=user_id, reciver_checked=True).annotate(count=Count('sender_name'))
        shared_item_list = []
        type_graph_result_shared = []
        for row in shared_data:
            sender_name = row['sender_name']
            shared_item = ShareFile.objects.filter(reciver_id=user_id, reciver_checked=True, sender_name=sender_name).order_by('-id')[0:7]
            datas = {}
            datas['folder_name'] = sender_name
            item_list = []
            current_file_type = []
            current_file_graph = []
            for item in shared_item:
                data = {}
                if item.file_id != "":
                    url = str(item.file_id)
                    a = urlparse(url)
                    file_name = os.path.basename(a.path)
                    name, ext = os.path.splitext(file_name)
                    data[item.id] = ext
                    current_file_type.append(data)
                    icon = get_icon(ext.lower())
                    item_list.append({'icon': icon,'reciver':item.reciver,'sender_name': item.sender_name, 'file_url': item.file_id.url, 'file_name': file_name, 'file_id': item.id})
            datas['file'] = item_list
            shared_item_list.append(datas)

            merged_dictionary = {}
            for dictionary in current_file_type:
                for key, value in dictionary.items():
                    merged_dictionary[key] = value

            count_dic = {}
            for k, v in merged_dictionary.items():
                count_dic[v] = count_dic.get(v, 0) + 1

            if len(count_dic)!= 0:
                for key, value in count_dic.items():
                    current_file_graph.append({
                        'name': str(key), 'y': value, 'selected': 'true'
                    })
            else:
                current_file_graph.append({
                    'name': 'capacity', 'y': 100
                })
            whole_type = {
                'folder_id': item.sender_name,
                'graph': current_file_graph
            }
            type_graph_result_shared.append(whole_type)

       

        # for items in shared_item:
        #     if items.file_id == "":
        #         items.delete()
        # paginator = Paginator(shared_item, 7)
        # page = request.GET.get('page', 1)

        # try:
        #     shared = paginator.page(page)
        # except PageNotAnInteger:
        #     shared = paginator.page(1)
        # except EmptyPage:
        #     shared = paginator.page(paginator.num_pages)
        # shared_pages = shared.paginator.page_range
        shared_pages = ''
        # rendering highchart into the fronend #
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

        current_user_folder = Folder.objects.filter(user_id_id=user_id)
        type_graph_result_inner = []
        for item in current_user_folder:
            current_files = FolderFile.objects.filter(folder_id=item.id)
            current_file_type = []
            current_file_graph = []
            for items in current_files:
                data = {}
                filepath = os.path.join(
                    settings.MEDIA_ROOT, str(items.file_name))
                name, extension = os.path.splitext(filepath)
                data[items.id] = extension
                current_file_type.append(data)

            merged_dictionary = {}
            for dictionary in current_file_type:
                for key, value in dictionary.items():
                    merged_dictionary[key] = value

            count_dic = {}
            for k, v in merged_dictionary.items():
                count_dic[v] = count_dic.get(v, 0) + 1

            if len(count_dic)!= 0:
                for key, value in count_dic.items():
                    current_file_graph.append({
                        'name': str(key), 'y': value, 'selected': 'true'
                    })
            else:
                current_file_graph.append({
                    'name': 'capacity', 'y': 100
                })
            whole_type = {
                'folder_id': item.id,
                'graph': current_file_graph
            }
            type_graph_result_inner.append(whole_type)

        # total folder , file , MB count
        total_folder = Folder.objects.filter(user_id_id=user_id).count()

        total_files = FolderFile.objects.filter(user_id_id=user_id).count()
        whole_size = FolderFile.objects.filter(user_id_id=user_id)
        full_folderfile_size = 0
        for fileitem in whole_size:
            file_full_path = os.path.join(
                settings.MEDIA_ROOT, str(fileitem.file_name))
            if os.path.isfile(file_full_path):
                file_size = os.path.getsize(str(file_full_path))
                full_folderfile_size += file_size
        if full_folderfile_size > 1073741824:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1073741824)) + " GB"
        elif full_folderfile_size > 1048576:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1048576)) + " MB"
        else:
            real_filefolder_size = str(
                round(int(full_folderfile_size)/1024)) + " KB"

        return render(request, 'beta_feature.html', {'real_filefolder_size': real_filefolder_size, 'total_folder': total_folder, 'total_files': total_files, 'graph_data_outer': graph_data_outer, 'type_graph_result_inner': type_graph_result_inner,'type_graph_result_shared': type_graph_result_shared, 'current_user_name': current_user_name, 'result': result, 'remaining_size': remaining_size, 'shared_item_list': shared_item_list, 'shared_pages': shared_pages, 'deletd_page_list': deletd_page_list, 'profile_pic': profile_pic, 'share_people': all_user, 'all_user': render_user, 'list_of_folder': all_folder, 'delete_folder_file': delete_folder_file, 'current_user_name_display': current_user_name_display})

class PasswordResetCustomView(PasswordResetView):
    template_name = 'password_reset.html'
    email_template_name = 'password_reset_email.html'
    success_url = reverse_lazy('password_reset_done')

    def form_valid(self, form):
        email = form.cleaned_data['email']
        user = User.objects.get(email=email)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = self.request.build_absolute_uri(reverse('password_reset_confirm', args=[uid, token]))
        send_mail(
            subject='Password Reset Request',
            message='Please click the following link to reset your password: ' + reset_link,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[email],
            fail_silently=False,
        )
        return super().form_valid(form)


def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        print("user", user)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            if new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                s = update_password(user, new_password)
                return redirect('password_reset_complete')
        return render(request, 'password_reset_confirm.html')
    else:
        return redirect('password_reset_invalid')

def update_password(user_id, new_password):
    try:
        registration = RegisterUser.objects.get(user_id=user_id)
        registration.password = new_password
        registration.save()
        return True
    except RegisterUser.DoesNotExist:
        return False
def password_reset_done(request):
    return render(request, 'password_reset_done.html')
def password_reset_complete(request):
    return render(request, 'password_reset_complete.html')


def password_reset_invalid(request):
    return render(request, 'password_reset_invalid.html')