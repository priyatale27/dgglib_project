from django.contrib import admin
from .models import RegisterUser,Folder,FolderFile,DeletedFileFolder,userfeedback, RecoveryDeletedFileFolder
from django.contrib.auth.models import User
import os


# Register your models here.

def delete_user(modeladmin, request, queryset):
    for obj in queryset:
        email = obj.email
        user = User.objects.get(email=email)
        user.delete()
        obj.delete()

class RegisterAdmin(admin.ModelAdmin):
    list_display = ['user_id','image_tag','email','default_size','uploaded_size']
    list_editable = ['default_size']
    actions = [delete_user]
admin.site.disable_action('delete_selected')

admin.site.register(RegisterUser,RegisterAdmin)
admin.site.register(Folder)

class FolderFileAdmin(admin.ModelAdmin):
    list_display = ['user_id','folder','file_name']
admin.site.register(FolderFile,FolderFileAdmin)

admin.site.register(DeletedFileFolder)


class feedbackAdmin(admin.ModelAdmin):
    list_display = ['email','feedback']

admin.site.register(userfeedback,feedbackAdmin)


class UploadFilesAdmin(admin.ModelAdmin):
    list_display = ['user_id','file_id','upload_file']

#admin.site.register(UploadFiles,UploadFilesAdmin)

class RecoveryDeletedFileFolderAdmin(admin.ModelAdmin):
    list_display = ['file_name','folder_name']

admin.site.register(RecoveryDeletedFileFolder,RecoveryDeletedFileFolderAdmin)