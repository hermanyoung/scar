from django.db import connection
from django.db.models.expressions import RawSQL
from myapp.models import User

# ruleid: python.django.security.cwe-089.django-raw-sql
users = User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")

# ruleid: python.django.security.cwe-089.django-raw-sql
users = User.objects.raw("SELECT * FROM users WHERE name = '%s'" % name)

# ruleid: python.django.security.cwe-089.django-raw-sql
users = User.objects.raw("SELECT * FROM users WHERE name = '{}'".format(name))

cursor = connection.cursor()
# ruleid: python.django.security.cwe-089.django-raw-sql
cursor.execute(f"DELETE FROM users WHERE id = {user_id}")

# ruleid: python.django.security.cwe-089.django-raw-sql
annotation = RawSQL(f"select count(*) from orders where user_id = {user_id}")

# ok: python.django.security.cwe-089.django-raw-sql
users = User.objects.raw("SELECT * FROM users WHERE name = %s", [name])

# ok: python.django.security.cwe-089.django-raw-sql
cursor.execute("DELETE FROM users WHERE id = %s", [user_id])

# ok: python.django.security.cwe-089.django-raw-sql
users = User.objects.filter(name=name)
