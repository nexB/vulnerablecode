# Generated by Django 4.2.2 on 2023-11-23 16:24

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Note",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        help_text="The object's unique global identifier",
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("acct", models.CharField(max_length=200)),
                ("content", models.TextField()),
                (
                    "created_at",
                    models.DateTimeField(
                        auto_now_add=True, help_text="A field to track when notes are created"
                    ),
                ),
                (
                    "updated_at",
                    models.DateTimeField(
                        auto_now=True, help_text="A field to track when notes are updated"
                    ),
                ),
                (
                    "reply_to",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="replies",
                        to="review.note",
                    ),
                ),
            ],
            options={
                "ordering": ["-updated_at"],
            },
        ),
        migrations.CreateModel(
            name="Person",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("summary", models.CharField(max_length=100)),
                ("public_key", models.TextField()),
                ("local", models.BooleanField(default=True)),
                (
                    "avatar",
                    models.ImageField(default="favicon-16x16.png", null=True, upload_to="uploads/"),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="RemoteActor",
            fields=[
                ("url", models.URLField(primary_key=True, serialize=False)),
                ("username", models.CharField(max_length=100)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name="Repository",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        help_text="The object's unique global identifier",
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("name", models.CharField(max_length=50)),
                ("url", models.URLField()),
                ("path", models.CharField(max_length=200)),
                ("remote_url", models.CharField(blank=True, max_length=300, null=True)),
            ],
        ),
        migrations.CreateModel(
            name="Reputation",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("voter", models.CharField(help_text="security@vcio.com", max_length=100)),
                ("acceptor", models.CharField(help_text="security@nexb.com", max_length=100)),
                ("positive", models.BooleanField(default=True)),
            ],
            options={
                "unique_together": {("voter", "acceptor", "positive")},
            },
        ),
        migrations.CreateModel(
            name="Vulnerability",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        help_text="The object's unique global identifier",
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("filename", models.CharField(max_length=255)),
                ("remote_url", models.CharField(blank=True, max_length=300, null=True)),
                (
                    "repo",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="review.repository"
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Service",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                (
                    "remote_actor",
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="review.remoteactor",
                    ),
                ),
                (
                    "user",
                    models.OneToOneField(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Review",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        help_text="The object's unique global identifier",
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("headline", models.CharField(help_text="the review title", max_length=300)),
                ("commit_id", models.CharField(max_length=300)),
                ("data", models.TextField(help_text="review data ex: vulnerability file")),
                (
                    "created_at",
                    models.DateTimeField(
                        auto_now_add=True, help_text="A field to track when review are created"
                    ),
                ),
                (
                    "updated_at",
                    models.DateTimeField(
                        auto_now=True, help_text="A field to track when review are updated"
                    ),
                ),
                ("remote_url", models.CharField(blank=True, max_length=300, null=True)),
                (
                    "status",
                    models.SmallIntegerField(
                        choices=[(0, "Open"), (1, "Draft"), (2, "Closed"), (3, "Merged")],
                        default=0,
                        help_text="status of review",
                    ),
                ),
                (
                    "author",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="review.person"
                    ),
                ),
                ("notes", models.ManyToManyField(blank=True, to="review.note")),
                ("reputation", models.ManyToManyField(blank=True, to="review.reputation")),
                (
                    "vulnerability",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="review.vulnerability"
                    ),
                ),
            ],
            options={
                "ordering": ["-updated_at"],
            },
        ),
        migrations.AddField(
            model_name="repository",
            name="admin",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE, to="review.service"
            ),
        ),
        migrations.CreateModel(
            name="Purl",
            fields=[
                ("summary", models.CharField(max_length=100)),
                ("public_key", models.TextField()),
                ("local", models.BooleanField(default=True)),
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        help_text="The object's unique global identifier",
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "string",
                    models.CharField(
                        help_text="PURL (no version) ex: @pkg:maven/org.apache.logging",
                        max_length=300,
                    ),
                ),
                ("notes", models.ManyToManyField(blank=True, to="review.note")),
                (
                    "remote_actor",
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="review.remoteactor",
                    ),
                ),
                (
                    "service",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="review.service",
                    ),
                ),
            ],
            options={
                "unique_together": {("service", "remote_actor", "string")},
            },
        ),
        migrations.AddField(
            model_name="person",
            name="remote_actor",
            field=models.OneToOneField(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to="review.remoteactor",
            ),
        ),
        migrations.AddField(
            model_name="person",
            name="user",
            field=models.OneToOneField(
                null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL
            ),
        ),
        migrations.AddField(
            model_name="note",
            name="reputation",
            field=models.ManyToManyField(blank=True, to="review.reputation"),
        ),
        migrations.CreateModel(
            name="Follow",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "person",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="review.person"
                    ),
                ),
                (
                    "purl",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="review.purl"
                    ),
                ),
            ],
            options={
                "ordering": ["-updated_at"],
            },
        ),
        migrations.AlterUniqueTogether(
            name="repository",
            unique_together={("admin", "name")},
        ),
    ]
