# Generated by Django 4.1.6 on 2023-06-27 10:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0016_alter_folder_folder_password'),
    ]

    operations = [
        migrations.AlterField(
            model_name='folder',
            name='folder_password',
            field=models.CharField(max_length=200, null=True),
        ),
    ]
