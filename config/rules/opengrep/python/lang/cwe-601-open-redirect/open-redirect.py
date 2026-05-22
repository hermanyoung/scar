from flask import redirect, request
from django.http import HttpResponseRedirect
from starlette.responses import RedirectResponse

# ruleid: python.lang.security.cwe-601.open-redirect
return redirect(user_input)

# ruleid: python.lang.security.cwe-601.open-redirect
return redirect(request.args.get("next"))

# ruleid: python.lang.security.cwe-601.open-redirect
return HttpResponseRedirect(request.GET.get("next"))

# ruleid: python.lang.security.cwe-601.open-redirect
return RedirectResponse(url=user_input)

# ok: python.lang.security.cwe-601.open-redirect
return redirect("/dashboard")

# ok: python.lang.security.cwe-601.open-redirect
return redirect(url_for("index"))

# ok: python.lang.security.cwe-601.open-redirect
return HttpResponseRedirect("/login")

# ok: python.lang.security.cwe-601.open-redirect
return RedirectResponse(url="/home")
