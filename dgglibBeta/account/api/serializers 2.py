from rest_framework import serializers
from account.models import FolderFile, Folder, RegisterUser, Profile, DeletedFileFolder


class FileDownloadSerializer(serializers.ModelSerializer):

        model = FolderFile
        fields = (
            'user_id',
            'folder',
            'file_name',
        )

class FolderSerializer(serializers.ModelSerializer):

    class Meta:
        model = Folder
        fields = (
            'id',
            'folder_name',
            'user_id'
        )

class MemberSerializer(serializers.ModelSerializer):

    class Meta:
        model = RegisterUser
        fields = (
            'user_id',
            'email',
            'token'
        )

class FolderUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = FolderFile
        fields = (
            '__all__'
        )

class UserDisplaySerializer(serializers.ModelSerializer):

    class Meta:
        model = RegisterUser
        fields = (
            'user_id',
        )

class ProfileSerializer(serializers.ModelSerializer):

    class Meta:
        model = Profile
        fields =   (
            '__all__'
        )

    def create(self, validated_data):

        user = Profile.objects.create(
            profile_id = validated_data['profile_id'],
            profile_name = validated_data['profile_name'],
            profile_email =validated_data['profile_email'],
            mobile_number = validated_data['mobile_number'],
            gender = validated_data['gender']

        )
        return user

class ChangePasswordSerializer(serializers.Serializer):

    model = RegisterUser

    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class TrashSerializer(serializers.ModelSerializer):

    class Meta:
        model = DeletedFileFolder
        fields = (
            '__all__'
        )


class FolderFileSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = FolderFile
        fields = (
            'only_file_name',
        )