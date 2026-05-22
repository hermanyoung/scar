from django.utils.safestring import mark_safe
from django.utils.html import format_html
import jinja2

# ruleid: python.django.security.cwe-079.django-mark-safe
html = mark_safe(f"<div>{user_input}</div>")

# ruleid: python.django.security.cwe-079.jinja2-autoescape-false
env = jinja2.Environment(loader=loader, autoescape=False)

# ok: python.django.security.cwe-079.django-mark-safe
html = format_html("<div>{}</div>", user_input)

# ok: python.django.security.cwe-079.jinja2-autoescape-false
env = jinja2.Environment(loader=loader, autoescape=True)

# ok: python.django.security.cwe-079.jinja2-autoescape-false
env = jinja2.Environment(loader=loader, autoescape=jinja2.select_autoescape())
