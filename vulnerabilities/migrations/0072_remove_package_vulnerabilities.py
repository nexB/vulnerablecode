# Generated by Django 4.2.15 on 2024-10-07 10:52

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0071_auto_20241007_1044"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="package",
            name="vulnerabilities",
        ),
    ]
