# Generated by Django 4.2.2 on 2023-09-02 18:12

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("review", "0002_alter_person_avatar_alter_purl_avatar"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="note",
            name="note_type",
        ),
    ]
