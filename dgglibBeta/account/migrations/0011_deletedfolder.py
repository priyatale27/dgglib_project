# Generated by Django 4.1.6 on 2023-06-19 10:23

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0010_folder_folder_password'),
    ]

    operations = [
        migrations.CreateModel(
            name='DeletedFolder',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('folder_name', models.CharField(blank=True, max_length=255)),
                ('created_date', models.DateTimeField(auto_now_add=True, null=True)),
                ('is_deleted', models.BooleanField(choices=[(True, 'Yes'), (False, 'No')], default=False)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='account.registeruser')),
            ],
        ),
    ]
