from django.urls import path,re_path
# from . views import *
from . views import register_render, login_render, home_page_render, shared_page_render, member_render, trash_render, beta_feature_render, PasswordResetCustomView, \
    password_reset_confirm, password_reset_complete, password_reset_invalid, password_reset_done
# upasana remove UserNewPass from url beacuse function is not defined in views.py
urlpatterns = [
    path('',login_render,name="login_render"),
    path('register/',register_render,name="register_render"),
    path('home/',home_page_render,name="index"),
    path('shared/',shared_page_render,name="shared"),
    path('members/',member_render,name="members"),
    path('trash/',trash_render,name="trash"),
    path('beta/',beta_feature_render,name="beta"),
    path('password_reset/', PasswordResetCustomView.as_view(), name='password_reset'),
    path('password_reset_confirm/<str:uidb64>/<str:token>/', password_reset_confirm, name='password_reset_confirm'),
    path('password_reset_complete/', password_reset_complete, name='password_reset_complete'),
    path('password_reset_invalid/', password_reset_invalid, name='password_reset_invalid'),
    path('password-reset-done/', password_reset_done, name='password_reset_done'),

]
