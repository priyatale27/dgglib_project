# Generated by Django 4.1.6 on 2023-06-19 06:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0009_folderfile_trash_path'),
    ]

    operations = [
        migrations.AddField(
            model_name='folder',
            name='folder_password',
            field=models.CharField(blank=True, max_length=200),
        ),
    ]
