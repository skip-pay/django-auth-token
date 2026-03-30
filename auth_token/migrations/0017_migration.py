from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_token', '0016_migration'),
    ]

    operations = [
        migrations.AddField(
            model_name='authorizationrequest',
            name='failed_attempts',
            field=models.PositiveIntegerField(default=0, verbose_name='failed attempts'),
        ),
    ]
