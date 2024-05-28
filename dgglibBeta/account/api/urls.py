from django.urls import path,re_path
# from . views import *
from . views import (UserDisplayAPIView,RegisterAPIView,LoginAPIView,ProfilePicAPIView,UpdateProfilePicView,frgt_pass,
                    ForgetPassID,AddFolderView,CreateFolderView,AddFileView,DeleteItemView,DeleteSharedItemView,DeleteTrashItemView,DeleteTrashFolderView,LogOutView,Emaildata,DeleteFolderView,
                    SearchFolderView,SearchPeopleView,trashItemDeleteView,SharePeopleFile,SharePeopleSharedFile,share_render,
                    SharedItemDeleteView,SharePeopleFolder,SharedSharePeopleFolder,share_render_folder,member_ajax_right,member_ajax_left,
                    trash_ajax_right,trash_ajax_left,share_ajax_right,share_ajax_left,folder_ajax_right,folder_ajax_left, deleteuserPic,trash_all_Item_DeleteView,
                    usernameupdate,UpdatePasswordView,email_activation_login,foldernameupdate,filenameupdate,Non_register_user_post,non_registered_download_file,
                    non_register_file_share_post,NonRegisterFileShareAPI,non_registered_download_folder_file,search_files_inside_folders,search_folderr,givefeedback,UserNewPass,
                    DeleteSingleItem,FileExistAPI,FileCountAPI,fileupload2,FileListAPI,FolderRenameAPI,TrashRetriveAPI,filedownload2,DeleteAppendAPI,password_reset_token_created,TrashlistAPI,FileDownloadAPIView,FolderListAPIView,MemberListAPIView,ForgotPasswordAPI,PiecharAPI,ProfileViewAPI,ChangePasswordView,
                    SharePeopleTrashFile, TrashSharePeopleFolder,Non_register_trash_user_post,non_registered_trash_download_file,RestoreTrashItemView, re_email_activation_login, ResendActivateAPIView, reactivate_render,folderpasswordupdate, validate_password, #folder_unlock_password
                     RestoreFolder, restore_all_view, forgotfolderpassword, folderpasswordreupdate, reset_folderpassword, reset_folder_password, reset_folder_password_template, reset_folder_password_logic,
                     CopyFilesView, MoveFilesView, folder_reorder, move_file)

# upasana remove UserNewPass from url beacuse function is not defined in views.py
urlpatterns = [
    # path('',login_render,name="login_render"),
    path('activate/<uidb64>/<token>/',email_activation_login,name="email_activation_login"),
    # path('register/',register_render,name="register_render"),
    path('register_ajax/',RegisterAPIView.as_view(),name="registration"),
    path('login_ajax/',LoginAPIView.as_view(),name="Login"),
    # path('home/',main_page_render,name="index"),
    path('profile_pic/',ProfilePicAPIView.as_view(),name="profile"),
    path('update_pic/',UpdateProfilePicView.as_view(),name="update_profile"),
    path('update_name/',usernameupdate,name="update_username"),

    path('update_folder/',foldernameupdate,name="update_foldername"),
    # path('update_file/',filenameupdate,name="filenameupdate"),
    path('filenameupdate/',filenameupdate,name="filenameupdate"),
    path('forget_pass/', ForgotPasswordAPI.as_view(), name="forget_pass"),
    path('update_pass/',UpdatePasswordView.as_view(),name="update_password"),
    # Delete Pic
    path('delete_pic/',deleteuserPic,name='deletpicture'),
    path('forget_pass/',frgt_pass,name="forget_pass"),
    path('forget_pass_ajax/',ForgetPassID.as_view(),name="forget_pass_ajax"),
    path('change_pass/<uidb64>/<token>/',Emaildata,name = "email_data_input"),
    path('share_render/<uidb64>/<token>/',share_render,name = "share_render"),
    # path('change_pass/',change_pass,name="change_pass"),
    path('change_pass_ajax/',UserNewPass.as_view(),name="change_pass_ajax"),
    path('add_folder/',AddFolderView.as_view(),name="add_folder"),
    path('create_folder/',CreateFolderView.as_view(),name="create_folder"),
    path('add_file/',AddFileView.as_view(),name="add_file"),
    path('delete_file/',DeleteItemView.as_view(),name="delete_file"),
    path('delete_shared_file/',DeleteSharedItemView.as_view(),name="delete_shared_file"),

    path('delete_trash_file/',DeleteTrashItemView.as_view(),name="delete_trash_file"),
    path('delete_trash_folder/',DeleteTrashFolderView.as_view(),name="delete_trash_folder"),
    
    
    path('delete_item/',DeleteSingleItem,name="delete_single_item"),
    path('shared_file_del/',SharedItemDeleteView.as_view(),name="shared_file_del"),
    path('share_file/',SharePeopleFile.as_view(),name="share_file"),
    path('share_shared_file/',SharePeopleSharedFile.as_view(),name="share_shared_file"),
    path('share_trash_file/',SharePeopleTrashFile.as_view(),name="share_trash_file"),
    # path('shared_pagi/',shared_pagi,name="shared_pagi"),
    path('share_folder/',SharePeopleFolder.as_view(),name="share_folder"),
    path('shared_share_folder/',SharedSharePeopleFolder.as_view(),name="shared_share_folder"),
    path('trash_share_folder/',TrashSharePeopleFolder.as_view(),name="trash_share_folder"),
    path('share_render_folder/<uidb64>/<token>/',share_render_folder,name = "share_render_folder"),
    path('search_folder/',SearchFolderView.as_view(),name="search_folder"),
    path('search_people/',SearchPeopleView.as_view(),name="search_people"),
    path('delete_folder/',DeleteFolderView.as_view(),name="delete_folder"),
    # path('member_pagi/',member_pagi,name="member_pagi"),
    # path('trash_pagi/',trash_pagi,name="trash_pagi"),
    path('trash_delete/',trashItemDeleteView.as_view(),name="trash_delete"),
    path('trash_all_delete/',trash_all_Item_DeleteView.as_view(),name="trash_all__delete"),
    path('Logout/',LogOutView.as_view(),name="Logout"),
    path('member_ajax_right/',member_ajax_right,name="member_ajax_right"),
    path('member_ajax_left/',member_ajax_left,name="member_ajax_left"),
    path('trash_ajax_right/',trash_ajax_right,name="trash_ajax_right"),
    path('trash_ajax_left/',trash_ajax_left,name="trash_ajax_left"),
    path('share_ajax_right/',share_ajax_right,name="share_ajax_right"),
    path('share_ajax_left/',share_ajax_left,name="share_ajax_left"),
    path('folder_ajax_right/',folder_ajax_right,name="folder_ajax_right"),
    path('folder_ajax_left/',folder_ajax_left,name="folder_ajax_left"),

    #for non_registered people folder download
    
    path('Non_register_trash_user_post/', Non_register_trash_user_post, name="Non_register_trash_user_post"),
    path('Non_register_user_post/', Non_register_user_post, name="Non_register_user_post"),
    path('non_registered_trash_download_file/<sharedtoken>/', non_registered_trash_download_file, name="non_registered_trash_download_file"),
    path('non_registered_download_file/<sharedtoken>/', non_registered_download_file, name="non_registered_download_file"),
    #for non_registered people file share
    path('non_register_file_share_post/', non_register_file_share_post, name="non_register_file_share_post"),
    #for non_registered_people file download
    path('non_registered_download_folder_file/<sharedtoken>/', non_registered_download_folder_file, name="non_registered_download_folder_file"),
    # for file search inside folder
    path('search_files_inside_folders/',search_files_inside_folders, name="search_files_inside_folders"),
    path('search_folderr/',search_folderr,name="search_folderr"),
    #path('trash_retrieve/',trash_retrieve, name="trash_retrieve"),
    path('feedback/',givefeedback.as_view(), name="givefeedback"),
    path('files_upload2/', fileupload2, name="files_upload2"),
    path('files_download2/<int:file>', filedownload2, name="files_download2"),
    path('files_download/', FileDownloadAPIView.as_view(), name="files_download"),
    #path('articles/<int:year>/<int:month>/<slug:slug>/', views.article_detail),
    path('member_list/', MemberListAPIView.as_view(), name="member_list"),
    path('user_diaplay/', UserDisplayAPIView.as_view(), name="user_display"),
    path('profile_display/', ProfileViewAPI.as_view(), name="profile_display"),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('piechart/', PiecharAPI.as_view(), name="piechart"),
    path('trash_list/', TrashlistAPI.as_view(), name='trash_list'),
    path('file_list/', FileListAPI.as_view(), name="file_list"),
    path('forgot_pass/conform/', password_reset_token_created, name="forgot_pass"),
    path('delete_append/', DeleteAppendAPI.as_view(), name='delete_append'),
    path('nonregister_fileshare/', NonRegisterFileShareAPI.as_view(), name='nonregister_fileshare'),
    path('trash_retrive/', TrashRetriveAPI.as_view(), name='trash_retrive'),
    path('folder_rename/', FolderRenameAPI.as_view(), name='folder_rename'),
    path('file_count/', FileCountAPI.as_view(), name='folder_rename'),
    path('file_exist/', FileExistAPI.as_view(), name='file_exist'),
    path('restore_trash_file/', RestoreTrashItemView.as_view(), name='restore_trash_file'),
    path('re_activate/<uidb64>/<token>/', re_email_activation_login, name="email_activation_login"),
    path('re_activate_ajax/', ResendActivateAPIView.as_view(), name="re_activate_ajax"),
    path('re_activate/', reactivate_render, name="re_activate"),
    path('folder_password/', folderpasswordupdate, name="folder_password"),
    # path('folder_unlock_password/', folder_unlock_password, name="folder_unlock_password"),
    path('validate_password/', validate_password, name='validate_password'),
    path('restore_trash_folder/', RestoreFolder.as_view(), name='restore_trash_folder'),
    path('restore-all/', restore_all_view, name='restore-all'),
    path('forgot_folder_password/', forgotfolderpassword, name="forgot_folder_password"),
    path('re_folder_password/', folderpasswordreupdate, name="re_folder_password"),
    path('reset_folderpassword_link/', reset_folder_password, name="reset_folderpassword_link"),
    path('reset_folderpassword_link/<str:folder_id>/<str:uuid>/', reset_folder_password_template, name="reset_folderpassword_link_template"),
    path('reset_folder_password_logic/<str:folder_id>/<str:uuid>/', reset_folder_password_logic, name='reset_folder_password_logic'),
    path('copy_files/', CopyFilesView.as_view(), name='copy_files'),
    path('move_files/', MoveFilesView.as_view(), name='move_files'),
    path('folder_reorder/', folder_reorder, name='folder_reorder'),
    path('move_file/<int:folder_id>/<int:file_id>/', move_file, name='move_file'),

]
