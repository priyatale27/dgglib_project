# Generated by Django 4.1.6 on 2023-06-08 06:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0006_remove_folder_folder_password_folderfile_files'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='folderfile',
            name='files',
        ),
        migrations.AlterField(
            model_name='deletedfilefolder',
            name='file_name',
            field=models.FileField(blank=True, max_length=255, upload_to=''),
        ),
        migrations.AlterField(
            model_name='folderfile',
            name='file_name',
            field=models.FileField(unique=True, upload_to=''),
        ),
    ]
