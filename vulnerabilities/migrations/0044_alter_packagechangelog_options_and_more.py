# Generated by Django 4.1.13 on 2023-12-25 10:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0043_alter_advisory_unique_together_advisory_url_and_more"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="packagechangelog",
            options={"ordering": ("-action_time",)},
        ),
        migrations.AlterModelOptions(
            name="vulnerabilitychangelog",
            options={"ordering": ("-action_time",)},
        ),
    ]
