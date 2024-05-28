from django.db import models
import os
import sys
from django.utils.html import mark_safe
from django.utils.html import format_html
from django.conf import settings
from passlib.hash import pbkdf2_sha256

# Create your models here.
def checkImage(instance, filename, **kwargs):
    """
    it checks the image to be only .jpg , .jpeg , .png
    """
    if filename:
        name, ext = os.path.splitext(filename)
        file_name = str(instance.id) + '_' + str(name)
        if ext.lower() == '.jpg' or ext.lower() == '.jpeg' or ext.lower() == '.png':
            return 'Digilocker_users_profile_pic/{}{}'.format(file_name, ext)
        else:
            raise TypeError

def share_func(instance,filename,**kwargs):
    temp_ret = 'shared_files/{}/{}'.format(filename['reciver_id'],filename['name'])
    print("Temp file is {}",temp_ret)
    return temp_ret


class RegisterUser(models.Model):
    upload_limit = [
        (102400, '100 MB'),
        (204800, '200 MB'),
        (409600, '400 MB'),
        (614400, '600 MB'),
        (819200, '800 MB'),    
        (1048576, '1GB'),
        (2097152, '2GB'),
        (3145728, '3GB'),
        (4194304, '4GB'),
        (5242880, '5GB'),
    ]
    user_id      = models.CharField(max_length=255,blank=True)
    password     = models.CharField(max_length=255,blank=True)
    email        = models.CharField(max_length=255,blank=True)
    profile_pic  = models.ImageField(upload_to=checkImage, null=True, blank=True)
    token        = models.CharField(max_length=300,blank =True)
    default_size = models.IntegerField(choices=upload_limit,default=204800)
    uploaded_size = models.IntegerField(default=0, blank=True)
    active_email = models.BooleanField(default=False)
    display_name = models.CharField(max_length=255,blank=True)
    
    def verify_password(self,password):
        return pbkdf2_sha256.verify(password,self.password)

    def image_tag(self):
        if self.profile_pic != '':
            return format_html('<img src="%smedia/%s" width="100" height="100" />' % (settings.ROOT_URL,self.profile_pic))
        else:
            return format_html('<img src="%sstatic/images/%s" width="100" height="100" />' % (settings.ROOT_URL,'inner1_NEW.png'))

    def __str__(self):
        return self.user_id


class Profile(models.Model):
    profile_id = models.IntegerField(blank=True)
    profile_name = models.CharField(max_length=50)
    profile_email = models.CharField(max_length=200)
    mobile_number = models.IntegerField()
    gender = models.CharField(max_length=50)


class Folder(models.Model):
    folder_name = models.TextField(blank=True)
    user_id = models.ForeignKey(RegisterUser,on_delete=models.CASCADE)
    folder_password = models.CharField(max_length=200, blank=True)
    is_locked = models.BooleanField(default=False)
    pass_present = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True,null=True)
    position = models.PositiveIntegerField(null=True)


    def __str__(self):
        return self.folder_name

class FolderFile(models.Model):
    user_id = models.ForeignKey(RegisterUser,on_delete=models.CASCADE)
    folder = models.ForeignKey(Folder,on_delete=models.CASCADE)
    file_name = models.FileField(max_length=255)
    only_file_name = models.TextField(blank=True)
    trash_path = models.CharField(max_length=255)
    created_date = models.DateTimeField(auto_now_add=True,null=True)
    file_order = models.PositiveIntegerField(default=0)


    # def image_tag(self):
    #         return mark_safe('<img src="%smedia/%s" width="100" height="100" />' % (settings.ROOT_URL,self.file_name))

class DeletedFileFolder(models.Model):
    deleted_type = [
        (True, "Yes"),
        (False, "No")
    ]
    # folder = models.ForeignKey(Folder,on_delete=models.CASCADE)
    # file = models.ForeignKey(FolderFile,on_delete=models.CASCADE)
    file_name = models.FileField(max_length=255,blank =True)
    folder_name = models.CharField(max_length=255,blank =True)
    user_id = models.ForeignKey(RegisterUser,on_delete=models.CASCADE)
    created_date = models.DateTimeField(auto_now_add=True,null=True)
    shared = models.BooleanField(default=False)
    is_deleted = models.BooleanField(choices=deleted_type,default=False)

class ShareFile(models.Model):
    sender_name = models.CharField(max_length=255,blank =True)
    reciver = models.CharField(max_length=255,blank =True)
    reciver_id = models.ForeignKey(RegisterUser,on_delete=models.CASCADE)# in table its receiver_id_id
    file_id = models.FileField(upload_to=share_func,blank=True, null=True)
    reciver_checked = models.BooleanField(default=False)
    token = models.CharField(max_length=300,blank =True)
    created_date = models.DateTimeField(auto_now_add=True,null=True)


#for non register user file/folder share
class NonRegisterFolderFile(models.Model):
    user_id = models.ForeignKey(RegisterUser,on_delete=models.CASCADE)
    folder_id = models.CharField(max_length=255,blank =True)
    file = models.CharField(max_length=255,blank =True)
    link = models.CharField(max_length=255,blank =True)
    email = models.CharField(max_length=255,blank=True)
    is_downloaded = models.BooleanField(default=False)
    insert_time = models.DateTimeField(null=True)
    token = models.CharField(max_length=255,blank =True)
    validity = models.CharField(max_length=20,blank = True)
    folder_name = models.CharField(max_length=255, blank=True, null=True)
    created_date = models.DateTimeField(auto_now_add=True,null=True)


class userfeedback(models.Model):
    feedbackid = models.AutoField(primary_key=True)
    email = models.CharField(max_length=255, blank=True, null=True)
    feedback = models.CharField(max_length=255, blank=True, null=True)

#test new features
class UploadFiles2(models.Model):
    user = models.ForeignKey(RegisterUser,on_delete=models.CASCADE)
    file = models.AutoField(primary_key=True)
    #upload_file = models.FileField(upload_to='files_upload/')
    deleted=models.BooleanField(default=False)
    password=models.CharField(max_length=8,default="none")
    file_name=models.CharField(max_length=255)
    file_ext=models.CharField(max_length=4)

class ShareFolder(models.Model):
    sender_name = models.CharField(max_length=255,blank =True)
    reciver = models.CharField(max_length=255,blank =True)
    reciver_id = models.ForeignKey(RegisterUser,on_delete=models.CASCADE)# in table its receiver_id_id
    file_id = models.FileField(upload_to=share_func,blank=True, null=True)
    reciver_checked = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True,null=True)


class RecoveryDeletedFileFolder(models.Model):
    file_name = models.FileField(max_length=255,blank =True)
    folder_name = models.CharField(max_length=255,blank =True)
    user_id = models.ForeignKey(RegisterUser,on_delete=models.CASCADE)
    created_date = models.DateTimeField(auto_now_add=True,null=True)
