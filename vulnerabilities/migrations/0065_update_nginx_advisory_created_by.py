# Generated by Django 4.2.15 on 2024-09-23 13:06

from django.db import migrations

"""
Update the created_by field on Advisory from the old qualified_name
to the new pipeline_id.
"""


def update_created_by(apps, schema_editor):
    from vulnerabilities.pipelines.nginx_importer import NginxImporterPipeline

    Advisory = apps.get_model("vulnerabilities", "Advisory")
    Advisory.objects.filter(created_by="vulnerabilities.importers.nginx.NginxImporter").update(
        created_by=NginxImporterPipeline.pipeline_id
    )



def reverse_update_created_by(apps, schema_editor):
    from vulnerabilities.pipelines.nginx_importer import NginxImporterPipeline

    Advisory = apps.get_model("vulnerabilities", "Advisory")
    Advisory.objects.filter(created_by=NginxImporterPipeline.pipeline_id).update(
        created_by="vulnerabilities.importers.nginx.NginxImporter"
    )


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0064_update_npm_pypa_advisory_created_by"),
    ]

    operations = [
        migrations.RunPython(update_created_by, reverse_code=reverse_update_created_by),
    ]